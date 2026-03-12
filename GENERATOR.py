#!/usr/bin/env python3

import requests
import base64
import socket
import ssl
import subprocess
import tempfile
import os
import logging
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# =========================
# CONFIG
# =========================

THREADS = 100
TCP_TIMEOUT = 3
TLS_TIMEOUT = 3

INPUT_FILE = "sources.txt"

OUTPUT_TXT = "subscription.txt"
OUTPUT_BASE64 = "subscription_base64.txt"

GEOIP_API = "http://ip-api.com/json/"

# =========================
# LOGGING
# =========================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

# =========================
# FLAG DATABASE
# =========================

country_flags = {
"DE":"🇩🇪","FI":"🇫🇮","US":"🇺🇸","GB":"🇬🇧","NL":"🇳🇱","FR":"🇫🇷",
"CA":"🇨🇦","RU":"🇷🇺","JP":"🇯🇵","SG":"🇸🇬","KR":"🇰🇷","HK":"🇭🇰",
"TR":"🇹🇷","UA":"🇺🇦","PL":"🇵🇱","CZ":"🇨🇿","IT":"🇮🇹","ES":"🇪🇸"
}

flag_regex = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")

# =========================
# DOWNLOAD SUBSCRIPTIONS
# =========================

def download_subscription(url):

    try:

        r = requests.get(url,timeout=20)

        if r.status_code != 200:
            return []

        text = r.text.strip()

        try:
            decoded = base64.b64decode(text).decode()
            if "://" in decoded:
                text = decoded
        except:
            pass

        return text.splitlines()

    except:
        return []


# =========================
# PARSE HOST PORT
# =========================

def parse_host_port(link):

    try:

        if "@" not in link:
            return None,None

        part = link.split("@")[1]

        host = part.split(":")[0]
        port = int(part.split(":")[1].split("?")[0])

        return host,port

    except:
        return None,None


# =========================
# TCP CHECK
# =========================

def tcp_check(host,port):

    try:

        sock = socket.create_connection((host,port),TCP_TIMEOUT)

        sock.close()

        return True

    except:

        return False


# =========================
# TLS CHECK
# =========================

def tls_check(host,port):

    try:

        context = ssl.create_default_context()

        sock = socket.create_connection((host,port),TLS_TIMEOUT)

        ssock = context.wrap_socket(sock,server_hostname=host)

        ssock.close()

        return True

    except:

        return False


# =========================
# GEOIP
# =========================

def get_country_flag(ip):

    try:

        r = requests.get(GEOIP_API+ip,timeout=5)

        data = r.json()

        code = data.get("countryCode")

        if code in country_flags:

            return country_flags[code]

    except:
        pass

    return None


# =========================
# FLAG ADD
# =========================

def add_flag_if_missing(link):

    if flag_regex.search(link):
        return link

    host,_ = parse_host_port(link)

    if not host:
        return None

    flag = get_country_flag(host)

    if not flag:
        return None

    if "#" in link:
        link = link + f" | {flag} |"
    else:
        link = link + f"#{flag}"

    return link


# =========================
# SINGBOX CHECK
# =========================

def singbox_check(link):

    try:

        with tempfile.NamedTemporaryFile(delete=False) as f:

            config = {
                "log":{"disabled":True},
                "outbounds":[{"type":"direct"}]
            }

            path = f.name

            f.write(str(config).encode())

        p = subprocess.run(
            ["sing-box","run","-c",path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10
        )

        os.remove(path)

        return p.returncode == 0

    except:

        return False


# =========================
# MAIN
# =========================

def main():

    logging.info("🚀 START GENERATOR")

    # load sources

    with open(INPUT_FILE) as f:

        sources = [x.strip() for x in f if x.strip()]

    logging.info(f"📡 SOURCES: {len(sources)}")

    # download subscriptions

    all_links = []

    with ThreadPoolExecutor(max_workers=THREADS) as ex:

        for result in ex.map(download_subscription,sources):

            all_links.extend(result)

    logging.info(f"⬇️ DOWNLOADED KEYS: {len(all_links)}")

    # remove duplicates

    unique = list(set(all_links))

    logging.info(f"♻️ UNIQUE KEYS: {len(unique)}")

    # TCP check

    tcp_alive = []

    def tcp_worker(link):

        host,port = parse_host_port(link)

        if not host:
            return None

        if tcp_check(host,port):
            return link

    with ThreadPoolExecutor(max_workers=THREADS) as ex:

        for r in ex.map(tcp_worker,unique):

            if r:
                tcp_alive.append(r)

    logging.info(f"🌐 TCP OK: {len(tcp_alive)}")

    # TLS check

    tls_alive = []

    def tls_worker(link):

        host,port = parse_host_port(link)

        if not host:
            return None

        if tls_check(host,port):
            return link

    with ThreadPoolExecutor(max_workers=THREADS) as ex:

        for r in ex.map(tls_worker,tcp_alive):

            if r:
                tls_alive.append(r)

    logging.info(f"🔐 TLS OK: {len(tls_alive)}")

    # add flags

    flagged = []

    with ThreadPoolExecutor(max_workers=50) as ex:

        for r in ex.map(add_flag_if_missing,tls_alive):

            if r:
                flagged.append(r)

    logging.info(f"🏳️ KEYS WITH FLAGS: {len(flagged)}")

    # singbox check

    working = []

    with ThreadPoolExecutor(max_workers=30) as ex:

        results = ex.map(singbox_check,flagged)

        for link,ok in zip(flagged,results):

            if ok:
                working.append(link)

    logging.info(f"✅ WORKING KEYS: {len(working)}")

    # write output

    date = datetime.now().strftime("%d-%m-%Y")

    header = f"""#profile-title:🇷🇺КРОТовыеТОННЕЛИ🇷🇺
#subscription-userinfo:upload=0; download=0; total=0; expire=0
#profile-update-interval:1
#support-url:🇷🇺КРОТовыеТОННЕЛИ🇷🇺
#profile-web-page-url:🇷🇺КРОТовыеТОННЕЛИ🇷🇺
#announce: АКТИВНЫХ ТОННЕЛЕЙ 🚀 {len(working)} | ОБНОВЛЕНО 📅 {date}
"""

    text = header + "\n".join(working)

    with open(OUTPUT_TXT,"w",encoding="utf8") as f:
        f.write(text)

    with open(OUTPUT_BASE64,"w") as f:
        f.write(base64.b64encode(text.encode()).decode())

    logging.info("💾 SUBSCRIPTIONS SAVED")


if __name__ == "__main__":
    main()
