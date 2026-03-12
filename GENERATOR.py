#!/usr/bin/env python3

import requests
import base64
import socket
import ssl
import subprocess
import tempfile
import os
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

# =========================
# CONFIG
# =========================

THREADS = 100
TCP_TIMEOUT = 3
TLS_TIMEOUT = 3

INPUT_FILE = "sources.txt"
OUTPUT_TXT = "subscription.txt"
OUTPUT_BASE64 = "subscription_base64.txt"

# =========================
# LOGGING
# =========================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

# =========================
# DOWNLOAD SUBSCRIPTIONS
# =========================

def download_subscription(url):

    try:
        r = requests.get(url, timeout=15)

        if r.status_code != 200:
            return []

        text = r.text.strip()

        # base64 subscription
        try:
            decoded = base64.b64decode(text).decode()
            if "://" in decoded:
                text = decoded
        except:
            pass

        return text.splitlines()

    except Exception:
        return []


# =========================
# TCP TEST
# =========================

def tcp_check(host, port):

    try:
        sock = socket.create_connection((host, port), TCP_TIMEOUT)
        sock.close()
        return True
    except:
        return False


# =========================
# TLS HANDSHAKE
# =========================

def tls_check(host, port):

    try:

        context = ssl.create_default_context()

        sock = socket.create_connection((host, port), TLS_TIMEOUT)
        ssock = context.wrap_socket(sock, server_hostname=host)

        ssock.close()

        return True

    except:
        return False


# =========================
# PARSE HOST PORT
# =========================

def parse_host_port(link):

    try:

        if "@" not in link:
            return None, None

        part = link.split("@")[1]

        host = part.split(":")[0]
        port = int(part.split(":")[1].split("?")[0])

        return host, port

    except:
        return None, None


# =========================
# SINGBOX CHECK
# =========================

def singbox_check(link):

    try:

        config = {
            "log": {"disabled": True},
            "outbounds": [
                {
                    "type": "vless",
                    "server": "1.1.1.1",
                    "server_port": 443
                }
            ]
        }

        with tempfile.NamedTemporaryFile(delete=False) as f:
            config_path = f.name
            f.write(str(config).encode())

        p = subprocess.run(
            ["sing-box", "run", "-c", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10
        )

        os.remove(config_path)

        return p.returncode == 0

    except:
        return False


# =========================
# MAIN
# =========================

def main():

    logging.info("START")

    # -------------------
    # load sources
    # -------------------

    with open(INPUT_FILE) as f:
        sources = [x.strip() for x in f if x.strip()]

    logging.info(f"SOURCES: {len(sources)}")

    # -------------------
    # download
    # -------------------

    all_links = []

    with ThreadPoolExecutor(max_workers=THREADS) as ex:

        results = ex.map(download_subscription, sources)

        for r in results:
            all_links.extend(r)

    logging.info(f"DOWNLOADED KEYS: {len(all_links)}")

    # -------------------
    # remove duplicates
    # -------------------

    unique = list(set(all_links))

    logging.info(f"UNIQUE KEYS: {len(unique)}")

    # -------------------
    # TCP CHECK
    # -------------------

    tcp_alive = []

    def tcp_worker(link):

        host, port = parse_host_port(link)

        if not host:
            return None

        if tcp_check(host, port):
            return link

    with ThreadPoolExecutor(max_workers=THREADS) as ex:

        for r in ex.map(tcp_worker, unique):

            if r:
                tcp_alive.append(r)

    logging.info(f"TCP OK: {len(tcp_alive)}")

    # -------------------
    # TLS CHECK
    # -------------------

    tls_alive = []

    def tls_worker(link):

        host, port = parse_host_port(link)

        if not host:
            return None

        if tls_check(host, port):
            return link

    with ThreadPoolExecutor(max_workers=THREADS) as ex:

        for r in ex.map(tls_worker, tcp_alive):

            if r:
                tls_alive.append(r)

    logging.info(f"TLS OK: {len(tls_alive)}")

    # -------------------
    # SINGBOX CHECK
    # -------------------

    working = []

    with ThreadPoolExecutor(max_workers=50) as ex:

        for r in ex.map(singbox_check, tls_alive):

            if r:
                working.append(r)

    logging.info(f"WORKING KEYS: {len(working)}")

    # -------------------
    # WRITE OUTPUT
    # -------------------

    date = datetime.now().strftime("%d-%m-%Y")

    header = f"""#profile-title:🇷🇺КРОТовыеТОННЕЛИ🇷🇺
#subscription-userinfo:upload=0; download=0; total=0; expire=0
#profile-update-interval:1
#support-url:🇷🇺КРОТовыеТОННЕЛИ🇷🇺
#profile-web-page-url:🇷🇺КРОТовыеТОННЕЛИ🇷🇺
#announce: АКТИВНЫХ ТОННЕЛЕЙ 🚀 {len(working)} | ОБНОВЛЕНО 📅 {date}
"""

    text = header + "\n".join(working)

    with open(OUTPUT_TXT, "w", encoding="utf8") as f:
        f.write(text)

    with open(OUTPUT_BASE64, "w") as f:
        f.write(base64.b64encode(text.encode()).decode())

    logging.info("FILES SAVED")


if __name__ == "__main__":
    main()
