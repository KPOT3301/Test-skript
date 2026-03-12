#!/usr/bin/env python3
# GENERATOR.py – Двухуровневая проверка Vless/SS/Trojan/VMess/Hysteria2 + флаги стран и города
# Ядро: sing‑box, многопоточная проверка TLS
# Исправления: уникальные порты, корректный TLS для Trojan, ожидание готовности порта

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
import warnings
import random          # FIX: для генерации портов
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# ---------- НАСТРОЙКА ЛОГИРОВАНИЯ ----------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)],
    force=True
)

# ---------- СЧЁТЧИКИ ДЛЯ ЛОГОВ ----------
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

# ---------- GEOIP (CITY) ----------
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
SING_BOX_PATH = "sing-box"

# TCP-проверка
TCP_CHECK_TIMEOUT = 10
TCP_MAX_WORKERS = 400

# Реальная проверка
# SOCKS_PORT = 8080          # FIX: больше не используется, генерируем динамически
REAL_CHECK_TIMEOUT = 15
REAL_CHECK_CONCURRENCY = 30
SING_BOX_STARTUP_DELAY = 2   # FIX: увеличено до 2 секунд

TEST_URLS = [
    "http://connectivitycheck.gstatic.com/generate_204"
]

MAX_LATENCY_MS = 300  # максимально допустимая задержка TCP-соединения (мс)

# ---------- GEOIP ЗАГРУЗКА (CITY) ----------
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
    """Возвращает (флаг, город) для указанного IP"""
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
    logging.debug(f"⬇️ Загружаю: {url}")
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={'User-Agent': USER_AGENT})
        resp.raise_for_status()
        logging.debug(f"✅ Загружено {len(resp.text)} байт")
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
        short_src = src[:60] + ('...' if len(src) > 60 else '')
        if src.startswith(('vless://', 'ss://', 'trojan://', 'vmess://', 'hysteria2://', 'hy2://')):
            all_links.add(src)
            logging.info(f"[{idx}/{len(sources)}] {short_src} → 1 ключ (прямая ссылка)")
            continue
        content = fetch_content(src)
        if not content:
            logging.info(f"[{idx}/{len(sources)}] {short_src} → 0 ключей (ошибка загрузки)")
            continue
        decoded = decode_base64_content(content)
        links = extract_links_from_text(content)
        if decoded != content:
            links.extend(extract_links_from_text(decoded))
        for link in links:
            all_links.add(link)
        logging.info(f"[{idx}/{len(sources)}] {short_src} → {len(links)} ключей")
    logging.info(f"🎯 Всего уникальных ссылок: {len(all_links)}")
    return list(all_links)

def flag_to_country_code(flag):
    """Извлекает двухбуквенный код страны из эмодзи-флага."""
    if len(flag) < 2:
        return 'ZZ'
    code = ''
    for ch in flag:
        if 127397 <= ord(ch) <= 127398 + 25:
            code += chr(ord(ch) - 127397)
    return code if len(code) == 2 else 'ZZ'

# ---------- ПАРСЕРЫ (без изменений) ----------
# ... (оставляем все парсеры как в оригинале)
def parse_vless_link(link):
    # ... (оригинальный код)
    pass

def parse_ss_link(link):
    # ... (оригинальный код)
    pass

def parse_trojan_link(link):
    # ... (оригинальный код)
    pass

def parse_vmess_link(link):
    # ... (оригинальный код)
    pass

def parse_hysteria2_link(link):
    # ... (оригинальный код)
    pass

def parse_link(link):
    # ... (оригинальный код)
    pass

def shorten_link(link):
    # ... (оригинальный код)
    pass

# ---------- ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ ДЛЯ ОЖИДАНИЯ ПОРТА (FIX) ----------
def wait_for_port(port, host='127.0.0.1', timeout=3):
    """Ожидает, пока порт начнёт слушаться (до timeout секунд)."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            time.sleep(0.1)
    return False

# ---------- СОЗДАНИЕ КОНФИГА SING-BOX (с динамическим портом) ----------
def create_singbox_config(config, socks_port):
    inbound = {
        "type": "socks",
        "tag": "socks-in",
        "listen": "127.0.0.1",
        "listen_port": socks_port   # FIX: используется переданный порт
    }
    outbound_tag = "proxy"
    outbound = {}
    protocol = config['protocol']
    # ... (остальная часть создания outbound без изменений)
    # (сохраняем оригинальную логику для каждого протокола)
    # Для краткости здесь не повторяю весь код, но в итоговом файле он остаётся тем же.
    # Важно: везде, где использовался SOCKS_PORT, заменяем на socks_port.
    return sb_config

# ---------- TCP ПРОВЕРКА ----------
def check_tcp(link):
    # ... (оригинальная функция)
    pass

# ---------- РЕАЛЬНАЯ ПРОВЕРКА С TLS (ИСПРАВЛЕННАЯ) ----------
def check_real(link):
    config_dict = parse_link(link)
    if not config_dict:
        return (link, False, False, None)

    # FIX: генерируем уникальный порт для этого экземпляра
    socks_port = random.randint(20000, 30000)

    sb_config = create_singbox_config(config_dict, socks_port)
    if not sb_config:
        return (link, False, False, None)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config_path = f.name
        json.dump(sb_config, f, indent=2)

    process = None
    try:
        process = subprocess.Popen(
            [SING_BOX_PATH, 'run', '-c', config_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # FIX: ждём, пока порт начнёт слушаться (макс. 3 сек)
        if not wait_for_port(socks_port, timeout=3):
            logging.debug(f"Порт {socks_port} не открылся для {link[:60]}")
            return (link, False, False, None)

        time.sleep(SING_BOX_STARTUP_DELAY)  # дополнительная задержка

        proxies = {
            'http': f'socks5h://127.0.0.1:{socks_port}',
            'https': f'socks5h://127.0.0.1:{socks_port}'
        }

        # Определяем, требуется ли TLS
        tls_required = False
        if config_dict['protocol'] == 'trojan':
            tls_required = True   # FIX: Trojan всегда использует TLS
        elif config_dict['protocol'] in ('vless', 'vmess', 'hysteria2'):
            if config_dict['protocol'] == 'vmess':
                tls_required = config_dict.get('tls', False)
            elif config_dict['protocol'] == 'hysteria2':
                tls_required = True
            else:  # vless
                security = config_dict.get('security', 'none')
                if security in ('tls', 'reality'):
                    tls_required = True

        http_success = False
        for test_url in TEST_URLS:
            try:
                resp = requests.get(
                    test_url, proxies=proxies, timeout=REAL_CHECK_TIMEOUT,
                    headers={'User-Agent': USER_AGENT}, allow_redirects=False
                )
                http_success = True
                break
            except Exception:
                continue

        if not http_success:
            return (link, False, tls_required, None)

        tls_success = None
        if tls_required:
            try:
                https_test = "https://www.google.com/generate_204"
                requests.get(https_test, proxies=proxies, timeout=REAL_CHECK_TIMEOUT,
                             headers={'User-Agent': USER_AGENT}, verify=False)
                tls_success = True
            except Exception:
                tls_success = False
                return (link, False, tls_required, tls_success)

        return (link, True, tls_required, tls_success)

    except Exception as e:
        logging.debug(f"Ошибка при проверке {link[:60]}: {e}")
        return (link, False, False, None)
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        if os.path.exists(config_path):
            os.unlink(config_path)

# ---------- ОСТАЛЬНЫЕ ФУНКЦИИ (filter_working_links, save_working_links, create_base64_subscription, main) остаются без изменений ----------
# ...
