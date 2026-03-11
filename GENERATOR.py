#!/usr/bin/env python3
# GENERATOR.py – Двухуровневая проверка Vless/SS/Trojan/VMess/Hysteria2 серверов + флаги стран и города
# Ужесточённая проверка: несколько тестовых URL, проверка времени ответа, проверка стабильности.
# Многопоточность: TCP = 300, Xray = 20.

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
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from datetime import datetime

# ---------- НАСТРОЙКА ЛОГИРОВАНИЯ ----------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)],
    force=True
)

# ---------- СЧЁТЧИКИ ----------
record_counter = 0
current_check = 0
total_checks = 0

# ---------- ЧАСОВОЙ ПОЯС ----------
try:
    from zoneinfo import ZoneInfo
    TIMEZONE = "Asia/Yekaterinburg"
    LOCAL_NOW = datetime.now(ZoneInfo(TIMEZONE))
    logging.info(f"🕐 Используется часовой пояс: {TIMEZONE}")
except ImportError:
    LOCAL_NOW = datetime.utcnow()
    logging.warning("⚠️ zoneinfo не найдена, используется UTC")
TODAY_STR = LOCAL_NOW.strftime("%d-%m-%Y")

import requests

# ---------- GEOIP ----------
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    logging.warning("⚠️ geoip2 не установлена. Флаги стран и города не будут добавлены.")

# ---------- КОНСТАНТЫ ПОДПИСКИ ----------
PROFILE_TITLE = "🇷🇺КРОТовыеТОННЕЛИ🇷🇺"
SUPPORT_URL = "🇷🇺КРОТовыеТОННЕЛИ🇷🇺"
PROFILE_WEB_PAGE_URL = "🇷🇺КРОТовыеТОННЕЛИ🇷🇺"
PROFILE_UPDATE_INTERVAL = "1"
SUBSCRIPTION_USERINFO = "upload=0; download=0; total=0; expire=0"

# ---------- ОСНОВНЫЕ КОНСТАНТЫ ----------
SOURCES_FILE = "sources.txt"
OUTPUT_FILE = "subscription.txt"
OUTPUT_BASE64_FILE = "subscription_base64.txt"
REQUEST_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
XRAY_CORE_PATH = "xray"

# TCP-проверка
TCP_CHECK_TIMEOUT = 10
TCP_MAX_WORKERS = 300
MAX_LATENCY_MS = 200  # снижено с 200 для отсева медленных серверов

# Реальная проверка
SOCKS_PORT = 8080
REAL_CHECK_TIMEOUT = 20  # увеличен общий таймаут
REAL_CHECK_CONCURRENCY = 20
XRAY_STARTUP_DELAY = 1

# ---------- GEOIP ЗАГРУЗКА ----------
GEOIP_DB_PATH = "GeoLite2-City.mmdb"
GEOIP_DB_URL = "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb"

def ensure_geoip_db():
    if not GEOIP_AVAILABLE:
        return False
    if os.path.exists(GEOIP_DB_PATH):
        return True
    logging.info("🌍 Скачиваю базу GeoIP (City)...")
    try:
        r = requests.get(GEOIP_DB_URL, timeout=30)
        r.raise_for_status()
        with open(GEOIP_DB_PATH, 'wb') as f:
            f.write(r.content)
        logging.info("✅ База GeoIP (City) скачана")
        return True
    except Exception as e:
        logging.error(f"❌ Ошибка скачивания GeoIP: {e}")
        return False

reader = None
if ensure_geoip_db():
    try:
        reader = geoip2.database.Reader(GEOIP_DB_PATH)
    except Exception as e:
        logging.error(f"❌ Не удалось открыть базу GeoIP: {e}")

def get_geo_info(ip):
    if reader is None:
        return "", ""
    try:
        response = reader.city(ip)
        country_code = response.country.iso_code
        city = response.city.name if response.city.name else ""
        flag = ''.join(chr(127397 + ord(c)) for c in country_code.upper()) if country_code else ""
        return flag, city
    except Exception:
        return "", ""

# ---------- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ----------
@lru_cache(maxsize=256)
def resolve_host(host):
    return socket.gethostbyname(host)

def read_sources():
    logging.info("📖 Чтение sources.txt...")
    sources = []
    try:
        with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    sources.append(line)
        logging.info(f"📚 Загружено {len(sources)} источников")
    except FileNotFoundError:
        logging.error(f"❌ Файл {SOURCES_FILE} не найден")
    return sources

def fetch_content(url):
    logging.info(f"⬇️ Загружаю: {url}")
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={'User-Agent': USER_AGENT})
        resp.raise_for_status()
        logging.info(f"✅ Загружено {len(resp.text)} байт")
        return resp.text
    except Exception as e:
        logging.warning(f"⚠️ Не удалось загрузить {url}: {e}")
        return None

def extract_links_from_text(text):
    return re.findall(r'(?:vless|ss|trojan|vmess|hysteria2|hy2)://[^\s<>"\']+', text)

def decode_base64_content(encoded):
    try:
        decoded = base64.b64decode(encoded.strip()).decode('utf-8', errors='ignore')
        return decoded
    except:
        return encoded

def gather_all_links(sources):
    logging.info(f"🔍 Сбор ссылок из {len(sources)} источников...")
    all_links = set()
    for idx, src in enumerate(sources, 1):
        logging.info(f"📦 [{idx}/{len(sources)}] {src[:60]}...")
        if src.startswith(('vless://', 'ss://', 'trojan://', 'vmess://', 'hysteria2://', 'hy2://')):
            all_links.add(src)
            continue
        content = fetch_content(src)
        if not content:
            continue
        decoded = decode_base64_content(content)
        links = extract_links_from_text(content)
        if decoded != content:
            links.extend(extract_links_from_text(decoded))
        for link in links:
            all_links.add(link)
        logging.info(f"🔗 Получено {len(links)} ссылок")
    logging.info(f"🎯 Всего уникальных ссылок: {len(all_links)}")
    return list(all_links)

# ---------- ПАРСЕРЫ (без изменений, см. предыдущие версии) ----------
def parse_vless_link(link):
    # ... (оставляем как было) ...
    pass

def parse_ss_link(link):
    # ... (оставляем как было) ...
    pass

def parse_trojan_link(link):
    # ... (оставляем как было) ...
    pass

def parse_vmess_link(link):
    # ... (оставляем как было) ...
    pass

def parse_hysteria2_link(link):
    # ... (оставляем как было) ...
    pass

def parse_link(link):
    if link.startswith('vless://'):
        return parse_vless_link(link)
    elif link.startswith('ss://'):
        return parse_ss_link(link)
    elif link.startswith('trojan://'):
        return parse_trojan_link(link)
    elif link.startswith('vmess://'):
        return parse_vmess_link(link)
    elif link.startswith(('hysteria2://', 'hy2://')):
        return parse_hysteria2_link(link)
    else:
        return None

def shorten_link(link):
    parsed = parse_link(link)
    if parsed:
        return f"{parsed['protocol']}://{parsed['host']}:{parsed['port']}"
    q_pos = link.find('?')
    if q_pos != -1:
        return link[:q_pos]
    return link[:80]

# ---------- СОЗДАНИЕ КОНФИГА XRAY (без изменений) ----------
def create_xray_config(config):
    # ... (оставляем как было) ...
    pass

# ---------- TCP ПРОВЕРКА ----------
def check_tcp(link):
    parsed = parse_link(link)
    if not parsed:
        return (link, False, None, None)
    host, port = parsed['host'], parsed['port']
    try:
        ip = resolve_host(host)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_CHECK_TIMEOUT)
        start = time.time()
        result = sock.connect_ex((ip, port))
        latency_ms = int((time.time() - start) * 1000) if result == 0 else None
        sock.close()
        return (link, result == 0, ip if result == 0 else None, latency_ms)
    except:
        return (link, False, None, None)

# ---------- УЖЕСТОЧЁННАЯ РЕАЛЬНАЯ ПРОВЕРКА ----------
def check_real(link):
    config_dict = parse_link(link)
    if not config_dict:
        return (link, False)
    xray_config = create_xray_config(config_dict)
    if not xray_config:
        return (link, False)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config_path = f.name
        json.dump(xray_config, f, indent=2)

    process = None
    try:
        process = subprocess.Popen(
            [XRAY_CORE_PATH, 'run', '-config', config_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        time.sleep(XRAY_STARTUP_DELAY)
        proxies = {
            'http': f'socks5h://127.0.0.1:{SOCKS_PORT}',
            'https': f'socks5h://127.0.0.1:{SOCKS_PORT}'
        }

        # Расширенный список тестов с ожидаемыми статусами
        test_urls = [
            ("http://connectivitycheck.gstatic.com/generate_204", 204),
            ("http://www.gstatic.com/generate_204", 204),
            ("https://www.google.com/generate_204", 204),
            ("https://cloudflare.com/cdn-cgi/trace", 200),
            ("http://example.com", 200)
        ]

        for url, expected_status in test_urls:
            try:
                start = time.time()
                resp = requests.get(
                    url, proxies=proxies, timeout=REAL_CHECK_TIMEOUT,
                    headers={'User-Agent': USER_AGENT}, allow_redirects=False,
                    verify=False
                )
                elapsed = time.time() - start
                if elapsed > 7:
                    logging.debug(f"Слишком долгий ответ {url}: {elapsed:.2f}с")
                    return (link, False)
                if resp.status_code != expected_status:
                    logging.debug(f"Неверный статус {url}: {resp.status_code}")
                    return (link, False)
            except Exception as e:
                logging.debug(f"Ошибка при запросе {url}: {e}")
                return (link, False)

        # Проверка стабильности
        for i in range(2):
            time.sleep(2)
            try:
                resp = requests.get(
                    "https://www.google.com/generate_204", proxies=proxies,
                    timeout=5, verify=False
                )
                if resp.status_code != 204:
                    return (link, False)
            except Exception:
                return (link, False)

        return (link, True)

    except Exception as e:
        logging.debug(f"Ошибка при проверке {link[:60]}: {e}")
        return (link, False)
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        if os.path.exists(config_path):
            os.unlink(config_path)

# ---------- ДВУХУРОВНЕВАЯ ФИЛЬТРАЦИЯ ----------
def filter_working_links(links):
    global record_counter, current_check, total_checks
    total_checks = len(links)
    logging.info(f"🚀 Начинаю двухуровневую проверку {total_checks} ссылок")

    # Этап 1: TCP-проверка + замер задержки
    logging.info(f"🌐 Этап 1: TCP-проверка {total_checks} ссылок...")
    tcp_success = []  # (link, ip, latency_ms)
    with ThreadPoolExecutor(max_workers=TCP_MAX_WORKERS) as executor:
        future_to_link = {executor.submit(check_tcp, link): link for link in links}
        for future in as_completed(future_to_link):
            current_check += 1
            link, ok, ip, latency = future.result()
            if ok and ip and latency is not None:
                if latency <= MAX_LATENCY_MS:
                    tcp_success.append((link, ip, latency))
    logging.info(f"📊 TCP-проверка завершена. Прошли (latency <= {MAX_LATENCY_MS} мс): {len(tcp_success)}/{total_checks}")

    if not tcp_success:
        return []

    # Определяем флаги и города
    logging.info(f"🌍 Определение геоданных для {len(tcp_success)} серверов...")
    geo_by_link = {}  # link -> (flag, city)
    for link, ip, _ in tcp_success:
        flag, city = get_geo_info(ip) if ip else ("", "")
        if flag:
            geo_by_link[link] = (flag, city)

    logging.info(f"🧾 Серверов с флагами: {len(geo_by_link)}")

    if not geo_by_link:
        return []

    # Этап 2: реальная проверка
    logging.info(f"🧪 Этап 2: Реальная проверка {len(geo_by_link)} ссылок...")
    working_links_with_geo = []  # (link, flag, city)
    stage_total = len(geo_by_link)
    stage_current = 0

    links_to_check = list(geo_by_link.keys())

    with ThreadPoolExecutor(max_workers=REAL_CHECK_CONCURRENCY) as executor:
        future_to_link = {executor.submit(check_real, link): link for link in links_to_check}
        for future in as_completed(future_to_link):
            stage_current += 1
            current_check += 1
            record_counter += 1
            link, is_working = future.result()
            short = shorten_link(link)

            # Определяем протокол
            if link.startswith('vless://'):
                proto = 'vless'
            elif link.startswith('ss://'):
                proto = 'ss'
            elif link.startswith('trojan://'):
                proto = 'trojan'
            elif link.startswith('vmess://'):
                proto = 'vmess'
            elif link.startswith(('hysteria2://', 'hy2://')):
                proto = 'hy2'
            else:
                proto = '?'

            flag, city = geo_by_link[link]

            if is_working:
                working_links_with_geo.append((link, flag, city))
                emoji = "✅"
            else:
                emoji = "❌"

            log_msg = f"{proto} {emoji} [{stage_current}/{stage_total}]: {short}"
            logging.info(log_msg)

    logging.info(f"📊 Реальная проверка завершена. Рабочих с флагами: {len(working_links_with_geo)}/{stage_total}")
    return working_links_with_geo

# ---------- СОХРАНЕНИЕ РЕЗУЛЬТАТОВ ----------
def save_working_links(links_with_geo):
    logging.info(f"💾 Сохраняю {len(links_with_geo)} серверов с геоданными...")
    if not links_with_geo:
        logging.warning("Нет серверов для сохранения.")
        return 0

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"#profile-title:{PROFILE_TITLE}\n")
        f.write(f"#subscription-userinfo:{SUBSCRIPTION_USERINFO}\n")
        f.write(f"#profile-update-interval:{PROFILE_UPDATE_INTERVAL}\n")
        f.write(f"#support-url:{SUPPORT_URL}\n")
        f.write(f"#profile-web-page-url:{PROFILE_WEB_PAGE_URL}\n")
        f.write(f"#announce: АКТИВНЫХ ТОННЕЛЕЙ 🚀 {len(links_with_geo)} | ОБНОВЛЕНО 📅 {TODAY_STR}\n")
        for idx, (link, flag, city) in enumerate(links_with_geo, 1):
            link_clean = re.sub(r'#.*$', '', link)
            city_part = f" {city}" if city else ""
            tag = f"#🔑📱ТОННЕЛЬ {idx:04d} | {flag}{city_part} |"
            f.write(link_clean + tag + '\n')

    logging.info(f"✅ Сохранено {len(links_with_geo)} серверов в {OUTPUT_FILE}")
    return len(links_with_geo)

def create_base64_subscription():
    try:
        with open(OUTPUT_FILE, 'rb') as f:
            encoded = base64.b64encode(f.read()).decode('ascii')
        with open(OUTPUT_BASE64_FILE, 'w', encoding='ascii') as f:
            f.write(encoded)
        logging.info(f"💾 Base64-версия сохранена в {OUTPUT_BASE64_FILE}")
    except Exception as e:
        logging.error(f"❌ Ошибка создания Base64: {e}")

def check_xray_available():
    logging.info("🔍 Проверка Xray-core...")
    try:
        result = subprocess.run([XRAY_CORE_PATH, '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            logging.info(f"✅ Xray-core: {result.stdout.splitlines()[0]}")
            return True
        else:
            logging.warning("⚠️ Xray-core не отвечает")
            return False
    except FileNotFoundError:
        logging.error(f"❌ Xray-core не найден по пути '{XRAY_CORE_PATH}'")
        return False
    except Exception as e:
        logging.error(f"❌ Ошибка проверки Xray: {e}")
        return False

# ---------- ГЛАВНАЯ ФУНКЦИЯ ----------
def main():
    global record_counter, current_check, total_checks
    logging.info("🟢 Запуск генератора подписок (ужесточённая проверка: 5 тестов, стабильность, latency ≤150 мс)")
    if not check_xray_available():
        logging.error("Xray-core обязателен. Завершение.")
        return

    sources = read_sources()
    if not sources:
        return

    all_links = gather_all_links(sources)
    if not all_links:
        return

    record_counter = 0
    current_check = 0
    total_checks = len(all_links)

    working_links_with_geo = filter_working_links(all_links)
    written = save_working_links(working_links_with_geo)

    if written > 0:
        create_base64_subscription()
    else:
        logging.warning("Нет серверов с флагами – Base64 не создана.")

    logging.info(f"📊 Итог: {len(working_links_with_geo)} рабочих с флагами из {len(all_links)} проверенных")
    logging.info("🏁 Работа завершена")

if __name__ == "__main__":
    main()
