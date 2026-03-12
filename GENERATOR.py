#!/usr/bin/env python3
"""
VPN Key Checker — параллельный режим для GitHub Actions

Режимы запуска:
  python GENERATOR.py prepare          — скачать ключи, дедублировать, разбить на чанки
  python GENERATOR.py check <index>    — проверить чанк с индексом (0..N-1)
  python GENERATOR.py merge            — собрать результаты и сохранить subscription
"""

import asyncio, base64, json, os, random, socket, ssl
import subprocess, sys, tempfile, time, urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional

import aiohttp
from aiohttp_socks import ProxyConnector


# ══════════════════════════════════════════════════════════════
#  Настройки
# ══════════════════════════════════════════════════════════════

SOURCES_FILE       = "sources.txt"
OUTPUT_FILE        = "subscription.txt"
OUTPUT_BASE64_FILE = "subscription_base64.txt"
CHUNKS_DIR         = "chunks"
RESULTS_DIR        = "results"
SINGBOX_PATH       = "sing-box"
TEST_URL           = "http://cp.cloudflare.com/generate_204"
TEST_TIMEOUT       = 10
TCP_TIMEOUT        = 5
TLS_TIMEOUT        = 5
MAX_CONCURRENT     = 10
SINGBOX_STARTUP    = 1.5
NUM_WORKERS        = 20

SEP = "-" * 62


# ══════════════════════════════════════════════════════════════
#  Цвета / лог
# ══════════════════════════════════════════════════════════════

RST  = "\033[0m"
BOLD = "\033[1m"
DIM  = "\033[2m"
RED  = "\033[31m"
GRN  = "\033[32m"
YLW  = "\033[33m"
CYN  = "\033[36m"
MGT  = "\033[35m"
BLU  = "\033[34m"
BG_GRN = "\033[42m"
BLK    = "\033[30m"

W = 64

def _ts():    return f"{DIM}{datetime.now().strftime('%H:%M:%S')}{RST}"
def _bar(done, total, width=28):
    pct = done / total if total else 0
    filled = int(width * pct)
    bar = GRN + "\u2588" * filled + DIM + "\u2591" * (width - filled) + RST
    return f"[{bar}] {BOLD}{done}{RST}{DIM}/{total}{RST} {DIM}({pct*100:.0f}%){RST}"

def _proto_tag(uri):
    if uri.startswith("vless://"):  return f"{MGT} VLESS  {RST}"
    if uri.startswith("vmess://"):  return f"{CYN} VMESS  {RST}"
    if uri.startswith("trojan://"): return f"{YLW} TROJAN {RST}"
    if uri.startswith("ss://"):     return f"{BLU} SS     {RST}"
    return f"{DIM} ???    {RST}"

def header(title):
    line = "\u2550" * W
    pad  = (W - len(title) - 2) // 2
    print(f"\n{CYN}{line}{RST}")
    print(f"{CYN}\u2551{RST}{' '*pad}{BOLD}{title}{RST}{' '*(W-pad-len(title)-1)}{CYN}\u2551{RST}")
    print(f"{CYN}{line}{RST}\n")

def section(title):
    print(f"\n{CYN}{'-'*W}{RST}")
    print(f"  {BOLD}{CYN}{title}{RST}")
    print(f"{CYN}{'-'*W}{RST}")

def log_ok(msg):   print(f"  {_ts()}  {GRN}\u2714{RST}  {msg}")
def log_warn(msg): print(f"  {_ts()}  {YLW}\u26a0{RST}  {msg}")
def log_err(msg):  print(f"  {_ts()}  {RED}\u2718{RST}  {msg}")
def log_info(msg): print(f"  {_ts()}  {CYN}\u00b7{RST}  {msg}")

REASON_ICON = {
    "parse":         "\U0001f534",
    "tcp":           "\U0001f50c",
    "tls":           "\U0001f512",
    "singbox-crash": "\U0001f4a5",
    "singbox-error": "\u2757",
    "http":          "\U0001f310",
    "ok":            "\u2705",
}


# ══════════════════════════════════════════════════════════════
#  Парсеры протоколов
# ══════════════════════════════════════════════════════════════

def _strip_fragment(uri): return uri.split("#")[0].strip()


def parse_vless(uri):
    try:
        uri = _strip_fragment(uri)
        parsed = urllib.parse.urlparse(uri)
        uuid, host, port = parsed.username, parsed.hostname, parsed.port
        p = urllib.parse.parse_qs(parsed.query)
        if not all([uuid, host, port]): return None
        ob = {"type": "vless", "server": host, "server_port": int(port), "uuid": uuid}
        flow = p.get("flow", [""])[0]
        if flow: ob["flow"] = flow
        sec = p.get("security", ["none"])[0]
        if sec in ("tls", "reality"):
            tls = {"enabled": True, "server_name": p.get("sni", [host])[0], "insecure": True}
            if sec == "reality":
                tls["reality"] = {"enabled": True, "public_key": p.get("pbk",[""])[0], "short_id": p.get("sid",[""])[0]}
            ob["tls"] = tls
        net = p.get("type", ["tcp"])[0]
        if net == "ws":
            ob["transport"] = {"type":"ws","path":p.get("path",["/"])[0],"headers":{"Host":p.get("host",[host])[0]}}
        elif net == "grpc":
            ob["transport"] = {"type":"grpc","service_name":p.get("serviceName",[""])[0]}
        elif net in ("h2","http"):
            ob["transport"] = {"type":"http","host":[p.get("host",[host])[0]],"path":p.get("path",["/"])[0]}
        return ob
    except Exception: return None


def parse_vmess(uri):
    try:
        encoded = uri[8:] + "=" * (-len(uri[8:]) % 4)
        data = json.loads(base64.b64decode(encoded).decode())
        host, port, uuid = data.get("add",""), int(data.get("port",0)), data.get("id","")
        if not all([host, port, uuid]): return None
        ob = {"type":"vmess","server":host,"server_port":port,"uuid":uuid,
              "security":data.get("scy","auto"),"alter_id":int(data.get("aid",0))}
        if data.get("tls") == "tls":
            ob["tls"] = {"enabled":True,"server_name":data.get("sni",host),"insecure":True}
        net = data.get("net","tcp")
        if net == "ws":
            ob["transport"] = {"type":"ws","path":data.get("path","/"),"headers":{"Host":data.get("host",host)}}
        elif net == "grpc":
            ob["transport"] = {"type":"grpc","service_name":data.get("path","")}
        elif net in ("h2","http"):
            ob["transport"] = {"type":"http","host":[data.get("host",host)],"path":data.get("path","/")}
        return ob
    except Exception: return None


def parse_trojan(uri):
    try:
        uri = _strip_fragment(uri)
        parsed = urllib.parse.urlparse(uri)
        pwd, host, port = parsed.username, parsed.hostname, parsed.port
        p = urllib.parse.parse_qs(parsed.query)
        if not all([pwd, host, port]): return None
        sec = p.get("security",["tls"])[0]
        tls = {"enabled":True,"server_name":p.get("sni",[host])[0],"insecure":True}
        if sec == "reality":
            tls["reality"] = {"enabled":True,"public_key":p.get("pbk",[""])[0],"short_id":p.get("sid",[""])[0]}
        ob = {"type":"trojan","server":host,"server_port":int(port),"password":pwd,"tls":tls}
        net = p.get("type",["tcp"])[0]
        if net == "ws":
            ob["transport"] = {"type":"ws","path":p.get("path",["/"])[0],"headers":{"Host":p.get("host",[host])[0]}}
        elif net == "grpc":
            ob["transport"] = {"type":"grpc","service_name":p.get("serviceName",[""])[0]}
        return ob
    except Exception: return None


def parse_ss(uri):
    try:
        uri = _strip_fragment(uri)
        body = uri[5:]
        if "?" in body: body = body.split("?")[0]
        if "@" in body:
            user_part, server_part = body.rsplit("@", 1)
            try:
                decoded = base64.b64decode(user_part + "=" * (-len(user_part) % 4)).decode()
                method, password = decoded.split(":", 1)
            except Exception:
                method, password = user_part.split(":", 1)
        else:
            decoded = base64.b64decode(body + "=" * (-len(body) % 4)).decode()
            mp, server_part = decoded.rsplit("@", 1)
            method, password = mp.split(":", 1)
        host, port_str = server_part.rsplit(":", 1)
        port = int(port_str)
        if not all([method, password, host, port]): return None
        return {"type":"shadowsocks","server":host,"server_port":port,"method":method,"password":password}
    except Exception: return None


def parse_key(uri):
    uri = uri.strip()
    if uri.startswith("vless://"):  return parse_vless(uri)
    if uri.startswith("vmess://"):  return parse_vmess(uri)
    if uri.startswith("trojan://"): return parse_trojan(uri)
    if uri.startswith("ss://"):     return parse_ss(uri)
    return None

def key_fingerprint(uri): return _strip_fragment(uri).lower()


# ══════════════════════════════════════════════════════════════
#  Загрузка подписок
# ══════════════════════════════════════════════════════════════

async def fetch_subscription(url, session):
    keys = []
    t0 = time.time()
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            raw = await resp.text(errors="ignore")
        try:
            candidate = base64.b64decode(raw.strip() + "=" * (-len(raw.strip()) % 4)).decode()
            if any(candidate.startswith(p) for p in ("vless://","vmess://","trojan://","ss://")):
                raw = candidate
        except Exception: pass
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith(("vless://","vmess://","trojan://","ss://")):
                keys.append(line)
        short = (url[:55]+"...") if len(url)>56 else url
        log_ok(f"{GRN}{str(len(keys)).rjust(4)}{RST} ключей  {DIM}{time.time()-t0:.1f}с{RST}  {DIM}{short}{RST}")
    except Exception as e:
        short = (url[:55]+"...") if len(url)>56 else url
        log_err(f"Ошибка  {DIM}{short}{RST}  {RED}{e}{RST}")
    return keys


# ══════════════════════════════════════════════════════════════
#  TCP / TLS
# ══════════════════════════════════════════════════════════════

def _get_host_port_sni(uri):
    uri_clean = _strip_fragment(uri)
    parsed = urllib.parse.urlparse(uri_clean)
    host, port = parsed.hostname or "", parsed.port or 443
    p = urllib.parse.parse_qs(parsed.query)
    if uri.startswith("vmess://"):
        try:
            encoded = uri[8:] + "=" * (-len(uri[8:]) % 4)
            data = json.loads(base64.b64decode(encoded).decode())
            host = data.get("add", host)
            port = int(data.get("port", port))
            sni  = data.get("sni", host)
            return host, port, sni if data.get("tls") == "tls" else None
        except Exception: return host, port, None
    sni     = p.get("sni", [host])[0]
    has_tls = p.get("security",["none"])[0] in ("tls","reality") or uri.startswith("trojan://")
    return host, port, (sni if has_tls else None)


async def check_tcp(host, port):
    try:
        loop = asyncio.get_event_loop()
        conn = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: socket.create_connection((host, port), timeout=TCP_TIMEOUT)),
            timeout=TCP_TIMEOUT + 1)
        conn.close()
        return True
    except Exception: return False


async def check_tls(host, port, sni):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        loop = asyncio.get_event_loop()
        def _hs():
            raw = socket.create_connection((host, port), timeout=TLS_TIMEOUT)
            ctx.wrap_socket(raw, server_hostname=sni).close()
        await asyncio.wait_for(loop.run_in_executor(None, _hs), timeout=TLS_TIMEOUT + 1)
        return True
    except Exception: return False


# ══════════════════════════════════════════════════════════════
#  sing-box
# ══════════════════════════════════════════════════════════════

def build_singbox_config(outbound, socks_port):
    return {
        "log": {"level": "fatal"},
        "dns": {"servers": [{"tag": "dns", "address": "8.8.8.8"}]},
        "inbounds": [{"type":"socks","tag":"socks-in","listen":"127.0.0.1","listen_port":socks_port}],
        "outbounds": [{**outbound, "tag":"proxy"}, {"type":"direct","tag":"direct"}],
        "route": {"final": "proxy"},
    }


async def test_key(uri, semaphore):
    t0 = time.time()
    async with semaphore:
        outbound = parse_key(uri)
        if outbound is None:
            return uri, False, "parse", (time.time()-t0)*1000

        host, port, sni = _get_host_port_sni(uri)
        if not host or not port:
            return uri, False, "parse", (time.time()-t0)*1000

        if not await check_tcp(host, port):
            return uri, False, "tcp", (time.time()-t0)*1000

        if sni and not await check_tls(host, port, sni):
            return uri, False, "tls", (time.time()-t0)*1000

        socks_port  = random.randint(20000, 59999)
        config_file = None
        process     = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                json.dump(build_singbox_config(outbound, socks_port), f)
                config_file = f.name
            process = subprocess.Popen(
                [SINGBOX_PATH, "run", "-c", config_file],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            await asyncio.sleep(SINGBOX_STARTUP)
            if process.poll() is not None:
                return uri, False, "singbox-crash", (time.time()-t0)*1000
            connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{socks_port}")
            async with aiohttp.ClientSession(connector=connector) as sess:
                async with sess.get(TEST_URL, timeout=aiohttp.ClientTimeout(total=TEST_TIMEOUT), allow_redirects=True) as resp:
                    ok = resp.status in (200, 204)
                    return uri, ok, ("ok" if ok else "http"), (time.time()-t0)*1000
        except Exception:
            return uri, False, "singbox-error", (time.time()-t0)*1000
        finally:
            if process and process.poll() is None:
                process.terminate()
                try:
                    await asyncio.wait_for(
                        asyncio.get_event_loop().run_in_executor(None, process.wait), timeout=3)
                except Exception: process.kill()
            if config_file:
                try: os.unlink(config_file)
                except OSError: pass


# ══════════════════════════════════════════════════════════════
#  РЕЖИМ: prepare
# ══════════════════════════════════════════════════════════════

async def mode_prepare():
    header("PREPARE  |  Загрузка и разбивка на чанки")

    if not Path(SOURCES_FILE).exists():
        log_err(f"Файл {BOLD}{SOURCES_FILE}{RST} не найден!")
        sys.exit(1)

    sources = [l.strip() for l in Path(SOURCES_FILE).read_text().splitlines()
               if l.strip() and not l.startswith("#")]
    if not sources:
        log_warn("sources.txt пустой."); sys.exit(1)

    section(f"ЗАГРУЗКА  ({len(sources)} источников)")
    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(*[fetch_subscription(u, session) for u in sources])

    all_keys = [k for batch in results for k in batch]

    section("ДЕДУПЛИКАЦИЯ")
    seen, unique = set(), []
    for k in all_keys:
        fp = key_fingerprint(k)
        if fp not in seen:
            seen.add(fp); unique.append(k)

    dupes = len(all_keys) - len(unique)
    log_info(f"Скачано    : {BOLD}{len(all_keys)}{RST}")
    log_info(f"Дубликатов : {YLW}{dupes}{RST}")
    log_ok  (f"Уникальных : {GRN}{BOLD}{len(unique)}{RST}")

    pc = {}
    for k in unique:
        for pfx in ("vless","vmess","trojan","ss"):
            if k.startswith(pfx+"://"): pc[pfx] = pc.get(pfx,0)+1
    log_info("Протоколы  : " + "  ".join(f"{BOLD}{p.upper()}{RST} {GRN}{n}{RST}" for p,n in pc.items()))

    section(f"РАЗБИВКА на {NUM_WORKERS} чанков")
    Path(CHUNKS_DIR).mkdir(exist_ok=True)
    chunks = [[] for _ in range(NUM_WORKERS)]
    for i, key in enumerate(unique):
        chunks[i % NUM_WORKERS].append(key)
    for idx, chunk in enumerate(chunks):
        (Path(CHUNKS_DIR) / f"chunk_{idx:02d}.txt").write_text("\n".join(chunk))
        log_info(f"chunk_{idx:02d}.txt  ->  {GRN}{len(chunk)}{RST} ключей")

    meta = {"total": len(unique), "workers": NUM_WORKERS, "chunks": [len(c) for c in chunks]}
    (Path(CHUNKS_DIR) / "meta.json").write_text(json.dumps(meta, indent=2))

    print(f"\n{CYN}{'='*W}{RST}")
    log_ok(f"Готово! {BOLD}{len(unique)}{RST} ключей -> {BOLD}{NUM_WORKERS}{RST} чанков")
    print(f"{CYN}{'='*W}{RST}\n")


# ══════════════════════════════════════════════════════════════
#  РЕЖИМ: check <chunk_index>
# ══════════════════════════════════════════════════════════════

async def mode_check(chunk_index: int):
    header(f"CHECK  |  Чанк #{chunk_index:02d}")

    chunk_file = Path(CHUNKS_DIR) / f"chunk_{chunk_index:02d}.txt"
    if not chunk_file.exists():
        log_err(f"Файл {chunk_file} не найден!")
        sys.exit(1)

    keys = [l.strip() for l in chunk_file.read_text().splitlines() if l.strip()]
    log_info(f"Ключей в чанке : {BOLD}{len(keys)}{RST}")

    section("sing-box")
    singbox_ok = False
    try:
        r = subprocess.run([SINGBOX_PATH, "version"], capture_output=True, timeout=5)
        ver = r.stdout.decode().splitlines()[0] if r.stdout else "?"
        log_ok(f"{BOLD}{ver}{RST}")
        singbox_ok = r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        log_warn("sing-box не найден!")

    section(f"ПРОВЕРКА  {len(keys)} ключей  |  параллельно: {MAX_CONCURRENT}")
    log_info(f"Таймауты: TCP {CYN}{TCP_TIMEOUT}с{RST}  TLS {CYN}{TLS_TIMEOUT}с{RST}  HTTP {CYN}{TEST_TIMEOUT}с{RST}")
    print()

    working = []
    stats   = {}
    done    = 0

    if singbox_ok:
        semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        tasks = [test_key(uri, semaphore) for uri in keys]
        for coro in asyncio.as_completed(tasks):
            uri, ok, reason, elapsed_ms = await coro
            done += 1
            stats[reason] = stats.get(reason, 0) + 1
            proto    = _proto_tag(uri)
            bar      = _bar(done, len(keys))
            host, _, _ = _get_host_port_sni(uri)
            host_str = (host[:28]+"...") if len(host)>29 else host.ljust(29)
            rl       = REASON_ICON.get(reason, "·")

            if ok:
                # ═══ РАБОЧИЙ КЛЮЧ — максимально заметная строка ═══
                working.append(uri)
                short_uri = (uri[:78]+"...") if len(uri)>79 else uri
                print(f"\n  {BG_GRN}{BLK}{BOLD} \u2705 WORKING #{len(working)} {RST}  {proto}  {GRN}{BOLD}{host_str}{RST}  {DIM}{elapsed_ms:.0f}ms{RST}")
                print(f"  {GRN}{SEP}{RST}")
                print(f"  {GRN}{BOLD}{short_uri}{RST}\n")
            else:
                # --- нерабочий — тусклая строка, не отвлекает -------
                print(f"  {DIM}\u2718 {proto} | {bar}  |  {host_str}  {rl}  {elapsed_ms:>6.0f}ms{RST}")
    else:
        log_warn("sing-box недоступен — сохраняем чанк без проверки.")
        working = keys

    section(f"ИТОГ чанка #{chunk_index:02d}")
    log_ok  (f"Рабочих       : {GRN}{BOLD}{len(working)}{RST}")
    log_info(f"TCP закрыт    : {YLW}{stats.get('tcp',0)}{RST}")
    log_info(f"TLS провален  : {YLW}{stats.get('tls',0)}{RST}")
    log_info(f"HTTP/прочее   : {RED}{stats.get('http',0)+stats.get('singbox-crash',0)+stats.get('singbox-error',0)}{RST}")

    Path(RESULTS_DIR).mkdir(exist_ok=True)
    result_file = Path(RESULTS_DIR) / f"result_{chunk_index:02d}.txt"
    result_file.write_text("\n".join(working))
    log_ok(f"Сохранено -> {BOLD}{result_file}{RST}")

    print(f"\n{CYN}{'='*W}{RST}\n")


# ══════════════════════════════════════════════════════════════
#  РЕЖИМ: merge
# ══════════════════════════════════════════════════════════════

def mode_merge():
    header("MERGE  |  Сборка результатов")

    result_files = sorted(Path(RESULTS_DIR).glob("result_*.txt"))
    if not result_files:
        log_err(f"Нет файлов результатов в '{RESULTS_DIR}/'!")
        sys.exit(1)

    section(f"ФАЙЛЫ: {len(result_files)} результатов")
    all_working = []
    for rf in result_files:
        keys = [l.strip() for l in rf.read_text().splitlines() if l.strip()]
        log_info(f"{rf.name}  ->  {GRN}{len(keys)}{RST} рабочих")
        all_working.extend(keys)

    seen, unique = set(), []
    for k in all_working:
        fp = key_fingerprint(k)
        if fp not in seen:
            seen.add(fp); unique.append(k)

    section("ИТОГ")
    log_info(f"Всего рабочих  : {BOLD}{len(all_working)}{RST}")
    if len(all_working) != len(unique):
        log_info(f"Доп. дублей    : {YLW}{len(all_working)-len(unique)}{RST}")
    log_ok(f"Финальных      : {GRN}{BOLD}{len(unique)}{RST}")

    section("СОХРАНЕНИЕ")
    content = "\n".join(unique)
    Path(OUTPUT_FILE).write_text(content, encoding="utf-8")
    log_ok(f"{BOLD}{len(unique)}{RST} ключей  ->  {BOLD}{OUTPUT_FILE}{RST}")
    encoded = base64.b64encode(content.encode()).decode()
    Path(OUTPUT_BASE64_FILE).write_text(encoded, encoding="utf-8")
    log_ok(f"Base64-версия   ->  {BOLD}{OUTPUT_BASE64_FILE}{RST}")

    print(f"\n{CYN}{'='*W}{RST}")
    print(f"  {GRN}{BOLD}\u2714  Готово! {len(unique)} рабочих ключей{RST}")
    print(f"{CYN}{'='*W}{RST}\n")


# ══════════════════════════════════════════════════════════════
#  Точка входа
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование:")
        print("  python GENERATOR.py prepare")
        print("  python GENERATOR.py check <index>")
        print("  python GENERATOR.py merge")
        sys.exit(1)

    mode = sys.argv[1].lower()
    if mode == "prepare":
        asyncio.run(mode_prepare())
    elif mode == "check":
        if len(sys.argv) < 3:
            print("Укажи индекс чанка: python GENERATOR.py check 0")
            sys.exit(1)
        asyncio.run(mode_check(int(sys.argv[2])))
    elif mode == "merge":
        mode_merge()
    else:
        print(f"Неизвестный режим: {mode}")
        sys.exit(1)
