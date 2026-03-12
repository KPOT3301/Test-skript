#!/usr/bin/env python3
import asyncio
import base64
import json
import os
import ssl
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

import aiohttp

# =========================
# CONFIG
# =========================

MAX_CONCURRENT = 400
THREADS = 20

TCP_TIMEOUT = 3
TLS_TIMEOUT = 4

INPUT_SOURCES = "sources.txt"

OUT_TXT = "subscription.txt"
OUT_B64 = "subscription_base64.txt"

TEST_URL = "https://www.google.com/generate_204"

# =========================
# LOGGER
# =========================

class Log:
    GREEN = "\033[92m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    YELLOW = "\033[93m"
    END = "\033[0m"

    @staticmethod
    def node_header(i, proto, host, port):
        print(f"\n{Log.BLUE}[{i:05d}] {proto.upper()} {host}:{port}{Log.END}")

    @staticmethod
    def step_ok(name, msg=""):
        print(f"   ├ {Log.GREEN}{name:<8} ✔{Log.END} {msg}")

    @staticmethod
    def step_fail(name, msg=""):
        print(f"   ├ {Log.RED}{name:<8} ✖{Log.END} {msg}")

    @staticmethod
    def result_ok():
        print(f"   └ {Log.GREEN}RESULT   WORKING{Log.END}")

    @staticmethod
    def result_fail():
        print(f"   └ {Log.RED}RESULT   FAIL{Log.END}")

    @staticmethod
    def info(msg):
        print(f"{Log.BLUE}[INFO]{Log.END} {msg}")

# =========================
# DOWNLOAD SOURCES
# =========================

async def fetch(session, url):
    try:
        async with session.get(url, timeout=20) as r:
            return await r.text()
    except:
        Log.step_fail("SOURCE", f"Failed to fetch {url}")
        return ""

async def load_sources():
    urls = [x.strip() for x in open(INPUT_SOURCES) if x.strip()]
    Log.info(f"Sources found: {len(urls)}")
    nodes = []

    async with aiohttp.ClientSession() as session:
        tasks = [fetch(session, u) for u in urls]
        results = await asyncio.gather(*tasks)

        for data in results:
            if not data:
                continue
            data = data.strip()
            try:
                decoded = base64.b64decode(data).decode()
                if "://" in decoded:
                    nodes.extend(decoded.splitlines())
                    continue
            except:
                pass
            nodes.extend(data.splitlines())
    return nodes

# =========================
# PARSER
# =========================

def parse_node(link):
    try:
        if link.startswith("vmess://"):
            raw = base64.b64decode(link[8:]).decode()
            j = json.loads(raw)
            return j["add"], int(j["port"]), True

        if link.startswith("vless://"):
            p = urlparse(link)
            tls = "security=tls" in link
            return p.hostname, p.port, tls

        if link.startswith("trojan://"):
            p = urlparse(link)
            return p.hostname, p.port, True

        if link.startswith("ss://"):
            p = urlparse(link)
            return p.hostname, p.port, False

        if link.startswith("hysteria2://"):
            p = urlparse(link)
            return p.hostname, p.port, True

    except:
        pass
    return None, None, False

# =========================
# TESTS
# =========================

async def dns_test(host):
    try:
        loop = asyncio.get_event_loop()
        ip = await loop.getaddrinfo(host, None)
        return True, ip[0][4][0]
    except:
        return False, None

async def tcp_test(host, port):
    start = time.time()
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=TCP_TIMEOUT)
        writer.close()
        latency = int((time.time() - start) * 1000)
        return True, latency
    except:
        return False, None

def tls_test(host, port):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except:
        return False

async def internet_test(link):
    config = {
        "log": {"level": "fatal"},
        "inbounds": [{
            "type": "socks",
            "listen": "127.0.0.1",
            "listen_port": 1080
        }],
        "outbounds": [
            {"type": "direct"}
        ]
    }
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "config.json")
        with open(path, "w") as f:
            json.dump(config, f)
        try:
            proc = subprocess.Popen(
                ["sing-box", "run", "-c", path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            await asyncio.sleep(1)
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    TEST_URL,
                    proxy="socks5://127.0.0.1:1080",
                    timeout=10
                ) as r:
                    ok = r.status == 204
            proc.kill()
            return ok
        except:
            return False

# =========================
# NODE CHECK
# =========================

async def check_node(link, sem, executor, stats, idx):
    async with sem:
        host, port, tls = parse_node(link)
        proto = link.split("://")[0]
        Log.node_header(idx, proto, host, port)

        # DNS
        ok, ip = await dns_test(host)
        if not ok:
            Log.step_fail("DNS", "resolve error")
            Log.result_fail()
            stats["fail"] += 1
            return None
        Log.step_ok("DNS", ip)

        # TCP
        ok, latency = await tcp_test(host, port)
        if not ok:
            Log.step_fail("TCP", "connection failed")
            Log.result_fail()
            stats["fail"] += 1
            return None
        Log.step_ok("TCP", f"{latency}ms")

        # TLS
        if tls:
            loop = asyncio.get_event_loop()
            ok = await loop.run_in_executor(executor, tls_test, host, port)
            if not ok:
                Log.step_fail("TLS", "handshake failed")
                Log.result_fail()
                stats["fail"] += 1
                return None
            Log.step_ok("TLS", "handshake ok")

        # INTERNET
        ok = await internet_test(link)
        if not ok:
            Log.step_fail("INTERNET", "no access")
            Log.result_fail()
            stats["fail"] += 1
            return None
        Log.step_ok("INTERNET", "204 google")

        Log.result_ok()
        stats["ok"] += 1
        return link

# =========================
# MAIN
# =========================

async def main():
    Log.info("Loading subscriptions...")
    nodes = await load_sources()
    nodes = list(set([x.strip() for x in nodes if "://" in x]))
    Log.info(f"Total nodes loaded: {len(nodes)}")

    sem = asyncio.Semaphore(MAX_CONCURRENT)
    executor = ThreadPoolExecutor(max_workers=THREADS)
    stats = {"ok": 0, "fail": 0, "total": len(nodes)}

    tasks = [
        check_node(n, sem, executor, stats, idx+1)
        for idx, n in enumerate(nodes)
    ]

    results = []
    for f in asyncio.as_completed(tasks):
        r = await f
        if r:
            results.append(r)
        else:
            stats["fail"] += 0  # уже учтено внутри check_node

    # Save results
    with open(OUT_TXT, "w") as f:
        f.write("\n".join(results))
    with open(OUT_B64, "w") as f:
        f.write(base64.b64encode("\n".join(results).encode()).decode())

    # ======================
    # SUMMARY STATISTICS
    # ======================
    total = stats["total"]
    ok = stats["ok"]
    fail = stats["fail"]
    percent = (ok / total) * 100 if total else 0

    print("\n" + "═" * 40)
    print("CHECK COMPLETE")
    print(f"TOTAL     {total}")
    print(f"WORKING   {ok}")
    print(f"FAILED    {fail}")
    print(f"SUCCESS   {percent:.2f}%")
    print("═" * 40)

# =========================
# RUN
# =========================

if __name__ == "__main__":
    asyncio.run(main())
