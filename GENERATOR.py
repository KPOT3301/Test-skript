#!/usr/bin/env python3
"""
VPN Key Checker
- Читает ссылки на подписки из sources.txt
- Скачивает и парсит VPN ключи
- Удаляет дубликаты
- Проверяет каждый ключ: TCP → TLS → sing-box
- Сохраняет рабочие ключи в subscription.txt и subscription_base64.txt
"""

import asyncio
import base64
import json
import os
import random
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional

import aiohttp
from aiohttp_socks import ProxyConnector


# ══════════════════════════════════════════════════════════════
#  Цвета и форматирование (ANSI)
# ══════════════════════════════════════════════════════════════

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"

    @staticmethod
    def b(s):  return f"\033[1m{s}\033[0m"
    @staticmethod
    def g(s):  return f"\033[32m{s}\033[0m"
    @staticmethod
    def r(s):  return f"\033[31m{s}\033[0m"
    @staticmethod
    def y(s):  return f"\033[33m{s}\033[0m"
    @staticmethod
    def c(s):  return f"\033[36m{s}\033[0m"
    @staticmethod
    def m(s):  return f"\033[35m{s}\033[0m"
    @staticmethod
    def d(s):  return f"\033[2m{s}\033[0m"


W = 64  # ширина блока


def _ts() -> str:
    return C.d(datetime.now().strftime("%H:%M:%S"))


def _bar(done: int, total: int, width: int = 28) -> str:
    pct    = done / total if total else 0
    filled = int(width * pct)
    bar    = C.GREEN + "█" * filled + C.DIM + "░" * (width - filled) + C.RESET
    return f"[{bar}] {C.BOLD}{done}{C.RESET}{C.DIM}/{total}{C.RESET} {C.DIM}({pct*100:.0f}%){C.RESET}"


def _proto_tag(uri: str) -> str:
    if uri.startswith("vless://"):   return f"\033[35m VLESS  \033[0m"
    if uri.startswith("vmess://"):   return f"\033[36m VMESS  \033[0m"
    if uri.startswith("trojan://"):  return f"\033[33m TROJAN \033[0m"
    if uri.startswith("ss://"):      return f"\033[34m SS     \033[0m"
    return f"\033[2m ???    \033[0m"


def header(title: str) -> None:
    line = "═" * W
    pad  = (W - len(title) - 2) // 2
    print(f"\n\033[36m{line}\033[0m")
    print(f"\033[36m║\033[0m{' ' * pad}\033[1m{title}\033[0m{' ' * (W - pad - len(title) - 1)}\033[36m║\033[0m")
    print(f"\033[36m{line}\033[0m\n")


def section(title: str) -> None:
    print(f"\n\033[36m{'─' * W}\033[0m")
    print(f"  \033[1m\033[36m{title}\033[0m")
    print(f"\033[36m{'─' * W}\033[0m")


def log_ok(msg: str)   -> None: print(f"  {_ts()}  \033[32m✔\033[0m  {msg}")
def log_warn(msg: str) -> None: print(f"  {_ts()}  \033[33m⚠\033[0m  {msg}")
def log_err(msg: str)  -> None: print(f"  {_ts()}  \033[31m✘\033[0m  {msg}")
def log_info(msg: str) -> None: print(f"  {_ts()}  \033[36m·\033[0m  {msg}")


# ─── Настройки ────────────────────────────────────────────────
SOURCES_FILE        = "sources.txt"
OUTPUT_FILE         = "subscription.txt"
OUTPUT_BASE64_FILE  = "subscription_base64.txt"
SINGBOX_PATH        = "sing-box"
TEST_URL            = "http://cp.cloudflare.com/generate_204"
TEST_TIMEOUT        = 10
TCP_TIMEOUT         = 5
TLS_TIMEOUT         = 5
MAX_CONCURRENT      = 10
SINGBOX_STARTUP     = 1.5
# ──────────────────────────────────────────────────────────────


# ══════════════════════════════════════════════════════════════
#  Парсеры протоколов → sing-box outbound конфиги
# ══════════════════════════════════════════════════════════════

def _strip_fragment(uri: str) -> str:
    return uri.split("#")[0].strip()


def parse_vless(uri: str) -> Optional[dict]:
    try:
        uri = _strip_fragment(uri)
        parsed = urllib.parse.urlparse(uri)
        uuid  = parsed.username
        host  = parsed.hostname
        port  = parsed.port
        p     = urllib.parse.parse_qs(parsed.query)
        if not all([uuid, host, port]):
            return None
        outbound: dict = {"type": "vless", "server": host, "server_port": int(port), "uuid": uuid}
        flow = p.get("flow", [""])[0]
        if flow:
            outbound["flow"] = flow
        security = p.get("security", ["none"])[0]
        if security in ("tls", "reality"):
            tls: dict = {"enabled": True, "server_name": p.get("sni", [host])[0], "insecure": True}
            if security == "reality":
                tls["reality"] = {"enabled": True, "public_key": p.get("pbk", [""])[0], "short_id": p.get("sid", [""])[0]}
            outbound["tls"] = tls
        net = p.get("type", ["tcp"])[0]
        if net == "ws":
            outbound["transport"] = {"type": "ws", "path": p.get("path", ["/"])[0], "headers": {"Host": p.get("host", [host])[0]}}
        elif net == "grpc":
            outbound["transport"] = {"type": "grpc", "service_name": p.get("serviceName", [""])[0]}
        elif net in ("h2", "http"):
            outbound["transport"] = {"type": "http", "host": [p.get("host", [host])[0]], "path": p.get("path", ["/"])[0]}
        return outbound
    except Exception:
        return None


def parse_vmess(uri: str) -> Optional[dict]:
    try:
        encoded = uri[8:]
        encoded += "=" * (-len(encoded) % 4)
        data = json.loads(base64.b64decode(encoded).decode())
        host = data.get("add", "")
        port = int(data.get("port", 0))
        uuid = data.get("id", "")
        if not all([host, port, uuid]):
            return None
        outbound: dict = {"type": "vmess", "server": host, "server_port": port, "uuid": uuid,
                          "security": data.get("scy", "auto"), "alter_id": int(data.get("aid", 0))}
        if data.get("tls") == "tls":
            outbound["tls"] = {"enabled": True, "server_name": data.get("sni", host), "insecure": True}
        net = data.get("net", "tcp")
        if net == "ws":
            outbound["transport"] = {"type": "ws", "path": data.get("path", "/"), "headers": {"Host": data.get("host", host)}}
        elif net == "grpc":
            outbound["transport"] = {"type": "grpc", "service_name": data.get("path", "")}
        elif net in ("h2", "http"):
            outbound["transport"] = {"type": "http", "host": [data.get("host", host)], "path": data.get("path", "/")}
        return outbound
    except Exception:
        return None


def parse_trojan(uri: str) -> Optional[dict]:
    try:
        uri = _strip_fragment(uri)
        parsed   = urllib.parse.urlparse(uri)
        password = parsed.username
        host     = parsed.hostname
        port     = parsed.port
        p        = urllib.parse.parse_qs(parsed.query)
        if not all([password, host, port]):
            return None
        security = p.get("security", ["tls"])[0]
        tls: dict = {"enabled": True, "server_name": p.get("sni", [host])[0], "insecure": True}
        if security == "reality":
            tls["reality"] = {"enabled": True, "public_key": p.get("pbk", [""])[0], "short_id": p.get("sid", [""])[0]}
        outbound: dict = {"type": "trojan", "server": host, "server_port": int(port), "password": password, "tls": tls}
        net = p.get("type", ["tcp"])[0]
        if net == "ws":
            outbound["transport"] = {"type": "ws", "path": p.get("path", ["/"])[0], "headers": {"Host": p.get("host", [host])[0]}}
        elif net == "grpc":
            outbound["transport"] = {"type": "grpc", "service_name": p.get("serviceName", [""])[0]}
        return outbound
    except Exception:
        return None


def parse_ss(uri: str) -> Optional[dict]:
    try:
        uri = _strip_fragment(uri)
        body = uri[5:]
        if "?" in body:
            body, _ = body.split("?", 1)
        if "@" in body:
            user_part, server_part = body.rsplit("@", 1)
            try:
                decoded = base64.b64decode(user_part + "=" * (-len(user_part) % 4)).decode()
                method, password = decoded.split(":", 1)
            except Exception:
                method, password = user_part.split(":", 1)
        else:
            decoded = base64.b64decode(body + "=" * (-len(body) % 4)).decode()
            method_pass, server_part = decoded.rsplit("@", 1)
            method, password = method_pass.split(":", 1)
        host, port_str = server_part.rsplit(":", 1)
        port = int(port_str)
        if not all([method, password, host, port]):
            return None
        return {"type": "shadowsocks", "server": host, "server_port": port, "method": method, "password": password}
    except Exception:
        return None


def parse_key(uri: str) -> Optional[dict]:
    uri = uri.strip()
    if uri.startswith("vless://"):  return parse_vless(uri)
    if uri.startswith("vmess://"):  return parse_vmess(uri)
    if uri.startswith("trojan://"): return parse_trojan(uri)
    if uri.startswith("ss://"):     return parse_ss(uri)
    return None


def key_fingerprint(uri: str) -> str:
    return _strip_fragment(uri).lower()


# ══════════════════════════════════════════════════════════════
#  Загрузка подписок
# ══════════════════════════════════════════════════════════════

async def fetch_subscription(url: str, session: aiohttp.ClientSession) -> list[str]:
    keys: list[str] = []
    t0 = time.time()
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            raw = await resp.text(errors="ignore")
        try:
            candidate = base64.b64decode(raw.strip() + "=" * (-len(raw.strip()) % 4)).decode()
            if any(candidate.startswith(p) for p in ("vless://", "vmess://", "trojan://", "ss://")):
                raw = candidate
        except Exception:
            pass
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith(("vless://", "vmess://", "trojan://", "ss://")):
                keys.append(line)
        elapsed = time.time() - t0
        short_url = (url[:55] + "…") if len(url) > 56 else url
        log_ok(f"{C.g(str(len(keys)).rjust(4))} ключей  {C.d(f'{elapsed:.1f}с')}  {C.d(short_url)}")
    except Exception as e:
        short_url = (url[:55] + "…") if len(url) > 56 else url
        log_err(f"Ошибка загрузки  {C.d(short_url)}  {C.r(str(e))}")
    return keys


# ══════════════════════════════════════════════════════════════
#  Предварительные проверки: TCP и TLS
# ══════════════════════════════════════════════════════════════

def _get_host_port_sni(uri: str) -> tuple[str, int, str | None]:
    uri_clean = _strip_fragment(uri)
    parsed    = urllib.parse.urlparse(uri_clean)
    host      = parsed.hostname or ""
    port      = parsed.port or 443
    p         = urllib.parse.parse_qs(parsed.query)
    if uri.startswith("vmess://"):
        try:
            encoded = uri[8:]
            encoded += "=" * (-len(encoded) % 4)
            data = json.loads(base64.b64decode(encoded).decode())
            host = data.get("add", host)
            port = int(data.get("port", port))
            sni  = data.get("sni", host)
            return host, port, sni if data.get("tls") == "tls" else None
        except Exception:
            return host, port, None
    sni      = p.get("sni", [host])[0]
    security = p.get("security", ["none"])[0]
    has_tls  = security in ("tls", "reality") or uri.startswith("trojan://")
    return host, port, (sni if has_tls else None)


async def check_tcp(host: str, port: int) -> bool:
    try:
        loop = asyncio.get_event_loop()
        conn = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: socket.create_connection((host, port), timeout=TCP_TIMEOUT)),
            timeout=TCP_TIMEOUT + 1,
        )
        conn.close()
        return True
    except Exception:
        return False


async def check_tls(host: str, port: int, sni: str) -> bool:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        loop = asyncio.get_event_loop()
        def _do_handshake():
            raw = socket.create_connection((host, port), timeout=TLS_TIMEOUT)
            tls_sock = ctx.wrap_socket(raw, server_hostname=sni)
            tls_sock.close()
        await asyncio.wait_for(loop.run_in_executor(None, _do_handshake), timeout=TLS_TIMEOUT + 1)
        return True
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════
#  Проверка через sing-box
# ══════════════════════════════════════════════════════════════

def build_singbox_config(outbound: dict, socks_port: int) -> dict:
    return {
        "log": {"level": "fatal", "disabled": False},
        "dns": {"servers": [{"tag": "dns", "address": "8.8.8.8"}]},
        "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": socks_port}],
        "outbounds": [{**outbound, "tag": "proxy"}, {"type": "direct", "tag": "direct"}],
        "route": {"final": "proxy"},
    }


async def test_key(uri: str, semaphore: asyncio.Semaphore) -> tuple[str, bool, str, float]:
    """Возвращает (uri, ok, reason, elapsed_ms)"""
    t0 = time.time()
    async with semaphore:
        outbound = parse_key(uri)
        if outbound is None:
            return uri, False, "parse", (time.time() - t0) * 1000

        host, port, sni = _get_host_port_sni(uri)
        if not host or not port:
            return uri, False, "parse", (time.time() - t0) * 1000

        # ── Шаг 1: TCP ────────────────────────────────────────
        if not await check_tcp(host, port):
            return uri, False, "tcp", (time.time() - t0) * 1000

        # ── Шаг 2: TLS ────────────────────────────────────────
        if sni and not await check_tls(host, port, sni):
            return uri, False, "tls", (time.time() - t0) * 1000

        # ── Шаг 3: sing-box ───────────────────────────────────
        socks_port  = random.randint(20000, 59999)
        config      = build_singbox_config(outbound, socks_port)
        config_file = None
        process     = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                json.dump(config, f)
                config_file = f.name
            process = subprocess.Popen(
                [SINGBOX_PATH, "run", "-c", config_file],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            await asyncio.sleep(SINGBOX_STARTUP)
            if process.poll() is not None:
                return uri, False, "singbox-crash", (time.time() - t0) * 1000
            connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{socks_port}")
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(TEST_URL, timeout=aiohttp.ClientTimeout(total=TEST_TIMEOUT), allow_redirects=True) as resp:
                    ok = resp.status in (200, 204)
                    return uri, ok, ("ok" if ok else "http"), (time.time() - t0) * 1000
        except Exception:
            return uri, False, "singbox-error", (time.time() - t0) * 1000
        finally:
            if process and process.poll() is None:
                process.terminate()
                try:
                    await asyncio.wait_for(
                        asyncio.get_event_loop().run_in_executor(None, process.wait), timeout=3)
                except Exception:
                    process.kill()
            if config_file:
                try:
                    os.unlink(config_file)
                except OSError:
                    pass


# ══════════════════════════════════════════════════════════════
#  Сохранение результатов
# ══════════════════════════════════════════════════════════════

def save_results(keys: list[str]) -> None:
    content = "\n".join(keys)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(content)
    log_ok(f"Сохранено {C.g(C.b(str(len(keys))))} ключей  →  {C.b(OUTPUT_FILE)}")
    encoded = base64.b64encode(content.encode()).decode()
    with open(OUTPUT_BASE64_FILE, "w", encoding="utf-8") as f:
        f.write(encoded)
    log_ok(f"Base64-версия               →  {C.b(OUTPUT_BASE64_FILE)}")


# ══════════════════════════════════════════════════════════════
#  Главная функция
# ══════════════════════════════════════════════════════════════

# Метки причин отказа
REASON_LABEL = {
    "parse":         ("🔴", "Неверный формат"),
    "tcp":           ("🔌", "TCP недоступен  "),
    "tls":           ("🔒", "TLS handshake   "),
    "singbox-crash": ("💥", "sing-box crash  "),
    "singbox-error": ("❗", "sing-box ошибка "),
    "http":          ("🌐", "HTTP провален   "),
    "ok":            ("✅", "Рабочий         "),
}


async def main() -> None:
    start_time = time.time()

    header("VPN Key Checker  ·  TCP › TLS › sing-box")

    # ── 1. Читаем sources.txt ──────────────────────────────────
    if not Path(SOURCES_FILE).exists():
        log_err(f"Файл {C.b(SOURCES_FILE)} не найден!")
        return

    sources = [
        line.strip()
        for line in Path(SOURCES_FILE).read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if not sources:
        log_warn(f"{SOURCES_FILE} пустой — нечего качать.")
        return

    # ── 2. Загружаем подписки ─────────────────────────────────
    section(f"📡  Загрузка подписок  ({len(sources)} источников)")
    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(*[fetch_subscription(url, session) for url in sources])

    all_keys: list[str] = [k for batch in results for k in batch]

    # ── 3. Дедупликация ───────────────────────────────────────
    section("🔁  Дедупликация")
    seen:        set[str]  = set()
    unique_keys: list[str] = []
    for key in all_keys:
        fp = key_fingerprint(key)
        if fp not in seen:
            seen.add(fp)
            unique_keys.append(key)

    dupes = len(all_keys) - len(unique_keys)
    log_info(f"Скачано всего  : {C.b(str(len(all_keys)))}")
    log_info(f"Дубликатов     : {C.y(str(dupes))}")
    log_ok  (f"Уникальных     : {C.g(C.b(str(len(unique_keys))))}")

    # Статистика протоколов
    proto_cnt: dict[str, int] = {}
    for k in unique_keys:
        for pfx in ("vless", "vmess", "trojan", "ss"):
            if k.startswith(pfx + "://"):
                proto_cnt[pfx] = proto_cnt.get(pfx, 0) + 1
    parts = "  ".join(f"{C.b(pfx.upper())} {C.g(str(n))}" for pfx, n in proto_cnt.items())
    log_info(f"Протоколы      : {parts}")

    # ── 4. Проверяем sing-box ─────────────────────────────────
    section("🔧  sing-box")
    singbox_available = False
    try:
        r = subprocess.run([SINGBOX_PATH, "version"], capture_output=True, timeout=5)
        version_line = r.stdout.decode().splitlines()[0] if r.stdout else "?"
        log_ok(f"{C.b(version_line)}")
        singbox_available = r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        log_warn(f"sing-box не найден по пути '{C.b(SINGBOX_PATH)}'")

    if not singbox_available:
        log_warn("Сохраняем уникальные ключи без проверки работоспособности.")
        section("💾  Сохранение")
        save_results(unique_keys)
        return

    # ── 5. Проверка ───────────────────────────────────────────
    section(f"🔍  Проверка  {len(unique_keys)} ключей  ·  параллельно: {MAX_CONCURRENT}")
    log_info(f"Таймауты: TCP {C.c(str(TCP_TIMEOUT)+'с')}  "
             f"TLS {C.c(str(TLS_TIMEOUT)+'с')}  "
             f"HTTP {C.c(str(TEST_TIMEOUT)+'с')}")
    print()

    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    working:  list[str] = []
    done = 0
    stats: dict[str, int] = {}

    tasks = [test_key(uri, semaphore) for uri in unique_keys]
    for coro in asyncio.as_completed(tasks):
        uri, ok, reason, elapsed_ms = await coro
        done += 1
        stats[reason] = stats.get(reason, 0) + 1

        # иконка и цвет строки
        if ok:
            icon  = "\033[32m✔\033[0m"
            working.append(uri)
        elif reason == "tcp":
            icon  = "\033[31m✘\033[0m"
        elif reason == "tls":
            icon  = "\033[33m✘\033[0m"
        else:
            icon  = "\033[31m✘\033[0m"

        proto     = _proto_tag(uri)
        bar       = _bar(done, len(unique_keys))
        host_str  = _get_host_port_sni(uri)[0]
        host_str  = (host_str[:28] + "…") if len(host_str) > 29 else host_str.ljust(29)
        reason_lbl, _ = REASON_LABEL.get(reason, ("·", reason))
        ms_str    = C.d(f"{elapsed_ms:>6.0f}ms")

        print(f"  {icon} {proto} \033[2m│\033[0m {bar}  \033[2m│\033[0m  "
              f"{C.d(host_str)}  {reason_lbl}  {ms_str}")

    # ── 6. Итоговая таблица ───────────────────────────────────
    total_time = time.time() - start_time
    section("📊  Результаты")

    total   = len(unique_keys)
    n_ok    = stats.get("ok", 0)
    pct_ok  = n_ok / total * 100 if total else 0

    # Большой прогресс-бар итога
    print(f"\n  {_bar(n_ok, total, width=36)}\n")

    rows = [
        ("✅", "Рабочих",          C.g(C.b(str(n_ok))),                          f"{pct_ok:.1f}%"),
        ("🔌", "TCP недоступен",   C.r(str(stats.get('tcp', 0))),                ""),
        ("🔒", "TLS провален",     C.y(str(stats.get('tls', 0))),                ""),
        ("💥", "sing-box crash",   C.r(str(stats.get('singbox-crash', 0))),      ""),
        ("❗", "sing-box ошибка",  C.r(str(stats.get('singbox-error', 0))),      ""),
        ("🌐", "HTTP провален",    C.r(str(stats.get('http', 0))),               ""),
        ("🔴", "Неверный формат",  C.d(str(stats.get('parse', 0))),              ""),
    ]
    for icon, label, value, extra in rows:
        extra_str = f"  {C.d(extra)}" if extra else ""
        print(f"  {icon}  {label:<22} {value}{extra_str}")

    print(f"\n  {C.d('─' * 40)}")
    print(f"  {'⏱'} {'Общее время':<22} {C.c(f'{total_time:.1f}с')}")
    print(f"  {'📦'} {'Проверено':<22} {C.b(str(total))}")
    print(f"  {'📁'} {'Источников':<22} {C.b(str(len(sources)))}")
    print()

    # ── 7. Сохранение ─────────────────────────────────────────
    section("💾  Сохранение")
    save_results(working)

    print(f"\n\033[36m{'═' * W}\033[0m")
    print(f"  \033[1m\033[32m✔  Готово!  {n_ok} рабочих ключей из {total}  ({pct_ok:.1f}%)\033[0m")
    print(f"\033[36m{'═' * W}\033[0m\n")


if __name__ == "__main__":
    asyncio.run(main())
