#!/usr/bin/env python3
# GENERATOR.py – улучшенная версия
# Добавлено:
# - IP cache
# - TLS handshake check
# - HTTP latency filter
# - private IP filter
# - limit keys per IP
# - стабильность проверки

import os
import re
import socket
import base64
import logging
import subprocess
import time
import json
import tempfile
import sys
import random
import ssl
import ipaddress
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from datetime import datetime

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests

# ---------- ЛОГИ ----------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)],
    force=True
)

# ---------- НАСТРОЙКИ ----------
XRAY_CORE_PATH = "xray"
REQUEST_TIMEOUT = 10

TCP_CHECK_TIMEOUT = 5
TCP_MAX_WORKERS = 400
TCP_ATTEMPTS = 3
MAX_LATENCY_MS = 300

REAL_CHECK_TIMEOUT = 15
REAL_CHECK_CONCURRENCY = 20
REAL_CHECK_ATTEMPTS = 1
MAX_HTTP_LATENCY_MS = 1000

MAX_PER_IP = 3

SOURCES_FILE = "sources.txt"

OUTPUT_RUS_FILE = "subscription_RUS.txt"
OUTPUT_RUS_BASE64_FILE = "subscription_RUS_base64.txt"

OUTPUT_OTHER_FILE = "subscription_OTHER.txt"
OUTPUT_OTHER_BASE64_FILE = "subscription_OTHER_base64.txt"

SOCKS_PORT_START = 10000
SOCKS_PORT_END = 11000

TEST_HTTP_URLS = [
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://www.msftncsi.com/ncsi.txt",
    "http://detectportal.firefox.com/success.txt"
]

TEST_HTTPS_URLS = [
    "https://www.google.com/generate_204",
    "https://cloudflare.com/cdn-cgi/trace"
]

DOH_URL = "https://1.1.1.1/dns-query?name=google.com&type=A"
DOH_HEADERS = {"Accept": "application/dns-json"}

# ---------- USER AGENTS ----------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
]

# ---------- CACHE ----------
ip_cache = {}
ip_count = {}

# ---------- TIME ----------
try:
    from zoneinfo import ZoneInfo
    LOCAL_NOW = datetime.now(ZoneInfo("Asia/Yekaterinburg"))
except:
    LOCAL_NOW = datetime.utcnow()

TODAY_STR = LOCAL_NOW.strftime("%d-%m-%Y")

# ---------- GEO ----------
reader = None
try:
    import geoip2.database
    if os.path.exists("GeoLite2-City.mmdb"):
        reader = geoip2.database.Reader("GeoLite2-City.mmdb")
except:
    pass

def get_geo_info(ip):

    if reader is None:
        return "", "", ""

    try:
        response = reader.city(ip)

        cc = response.country.iso_code
        city = response.city.name or ""

        flag = ''.join(chr(127397 + ord(c)) for c in cc)

        return flag, city, cc
    except:
        return "", "", ""

# ---------- HELPERS ----------

@lru_cache(maxsize=256)
def resolve_host(host):
    return socket.gethostbyname(host)

def is_private(ip):

    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return True

def find_free_port():

    for _ in range(10):

        port = random.randint(SOCKS_PORT_START, SOCKS_PORT_END)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('', port))
                return port
            except:
                continue

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

# ---------- TLS HANDSHAKE ----------

def check_tls_handshake(host, port, sni):

    try:

        ctx = ssl.create_default_context()

        with socket.create_connection((host, port), timeout=5) as sock:

            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:

                ssock.do_handshake()

        return True

    except:
        return False

# ---------- SOURCES ----------

def read_sources():

    sources = []

    with open(SOURCES_FILE, "r", encoding="utf-8") as f:

        for line in f:

            line = line.strip()

            if line and not line.startswith("#"):
                sources.append(line)

    logging.info(f"📚 источников: {len(sources)}")

    return sources

# ---------- FETCH ----------

def fetch_content(url):

    try:

        r = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": random.choice(USER_AGENTS)}
        )

        r.raise_for_status()

        return r.text

    except:
        return None

# ---------- EXTRACT ----------

def extract_links_from_text(text):

    return re.findall(
        r'(?:vless|ss|trojan|vmess|hysteria2|hy2)://[^\s<>"\']+',
        text
    )

# ---------- PARSER ----------

def parse_link(link):

    try:

        if link.startswith("vless://"):

            rest = link[8:]
            uuid, rest = rest.split("@", 1)

            parsed = urlparse("tcp://" + rest)

            params = parse_qs(parsed.query)

            sni = params.get("sni", [parsed.hostname])[0]

            return {
                "protocol": "vless",
                "uuid": uuid,
                "host": parsed.hostname,
                "port": parsed.port or 443,
                "security": params.get("security", ["none"])[0],
                "sni": sni,
                "explicit_sni": params.get("sni", [None])[0]
            }

        if link.startswith("trojan://"):

            parsed = urlparse(link)

            params = parse_qs(parsed.query)

            sni = params.get("sni", [parsed.hostname])[0]

            return {
                "protocol": "trojan",
                "host": parsed.hostname,
                "port": parsed.port or 443,
                "password": parsed.username,
                "sni": sni,
                "explicit_sni": params.get("sni", [None])[0]
            }

    except:
        return None

    return None

# ---------- TCP CHECK ----------

def check_tcp(link):

    parsed = parse_link(link)

    if not parsed:
        return link, False, None, None

    host = parsed["host"]
    port = parsed["port"]
    sni = parsed.get("explicit_sni")

    if not sni:
        return link, False, None, None

    try:

        ip = resolve_host(host)

        if is_private(ip):
            return link, False, None, None

        if ip in ip_cache:
            return link, ip_cache[ip], ip, None

        # TCP

        latencies = []

        for _ in range(TCP_ATTEMPTS):

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TCP_CHECK_TIMEOUT)

            start = time.time()

            result = sock.connect_ex((ip, port))

            latency = int((time.time() - start) * 1000)

            sock.close()

            if result != 0 or latency > MAX_LATENCY_MS:
                return link, False, None, None

            latencies.append(latency)

        # TLS

        if parsed.get("security") == "tls":

            if not check_tls_handshake(host, port, sni):
                return link, False, None, None

        return link, True, ip, min(latencies)

    except:
        return link, False, None, None

# ---------- XRAY CONFIG ----------

def create_xray_config(config, port):

    return {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth"}
        }],
        "outbounds": [{
            "protocol": config["protocol"],
            "settings": {}
        }]
    }

# ---------- REAL CHECK ----------

def check_real(link, ip):

    if ip in ip_cache:
        return link, ip_cache[ip]

    parsed = parse_link(link)

    port = find_free_port()

    cfg = create_xray_config(parsed, port)

    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        json.dump(cfg, f)
        path = f.name

    proc = None

    try:

        proc = subprocess.Popen(
            [XRAY_CORE_PATH, "run", "-config", path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        time.sleep(1)

        proxies = {
            "http": f"socks5h://127.0.0.1:{port}",
            "https": f"socks5h://127.0.0.1:{port}"
        }

        def single():

            for url in TEST_HTTP_URLS:

                try:

                    start = time.time()

                    requests.get(
                        url,
                        proxies=proxies,
                        timeout=REAL_CHECK_TIMEOUT,
                        headers={"User-Agent": random.choice(USER_AGENTS)}
                    )

                    latency = int((time.time() - start) * 1000)

                    if latency > MAX_HTTP_LATENCY_MS:
                        return False

                    return True

                except:
                    continue

            return False

        if not single():
            ip_cache[ip] = False
            return link, False

        time.sleep(1)

        if not single():
            ip_cache[ip] = False
            return link, False

        ip_cache[ip] = True

        return link, True

    except:

        ip_cache[ip] = False

        return link, False

    finally:

        if proc:
            proc.kill()

        os.unlink(path)

# ---------- MAIN FILTER ----------

def filter_links(links):

    tcp_ok = []

    with ThreadPoolExecutor(max_workers=TCP_MAX_WORKERS) as ex:

        futures = {ex.submit(check_tcp, l): l for l in links}

        for f in as_completed(futures):

            link, ok, ip, latency = f.result()

            if ok:
                tcp_ok.append((link, ip, latency))

    logging.info(f"TCP OK: {len(tcp_ok)}")

    working = []

    with ThreadPoolExecutor(max_workers=REAL_CHECK_CONCURRENCY) as ex:

        futures = {
            ex.submit(check_real, link, ip): (link, ip, latency)
            for link, ip, latency in tcp_ok
        }

        for f in as_completed(futures):

            link, ok = f.result()

            if not ok:
                continue

            _, ip, latency = futures[f]

            if ip_count.get(ip, 0) >= MAX_PER_IP:
                continue

            ip_count[ip] = ip_count.get(ip, 0) + 1

            flag, city, cc = get_geo_info(ip)

            if flag:
                working.append((link, flag, city, cc, latency))

    return working

# ---------- SAVE ----------

def save_links(data, file):

    with open(file, "w", encoding="utf-8") as f:

        for link, flag, city, _, _ in data:

            city_part = f" {city}" if city else ""

            f.write(f"{link}#{flag}{city_part}\n")

def create_base64(inp, out):

    with open(inp, "rb") as f:
        encoded = base64.b64encode(f.read()).decode()

    with open(out, "w") as f:
        f.write(encoded)

# ---------- MAIN ----------

def main():

    sources = read_sources()

    all_links = set()

    for s in sources:

        content = fetch_content(s)

        if not content:
            continue

        links = extract_links_from_text(content)

        for l in links:
            all_links.add(l)

    logging.info(f"links found: {len(all_links)}")

    working = filter_links(list(all_links))

    rus = [x for x in working if x[3] == "RU"]
    other = [x for x in working if x[3] != "RU"]

    save_links(rus, OUTPUT_RUS_FILE)
    save_links(other, OUTPUT_OTHER_FILE)

    create_base64(OUTPUT_RUS_FILE, OUTPUT_RUS_BASE64_FILE)
    create_base64(OUTPUT_OTHER_FILE, OUTPUT_OTHER_BASE64_FILE)

    logging.info(f"saved: {len(working)}")

if __name__ == "__main__":
    main()
