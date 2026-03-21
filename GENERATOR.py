#!/usr/bin/env python3
# GENERATOR.py – Ультра-усиленная версия с 5-кратными TCP/TLS проверками и одной реальной проверкой на 3 сайта (Google, Telegram, YouTube)
# Геолокация через MaxMind GeoLite2 City (скачивается в папку GeoIP, обновление раз в неделю)
# Фильтр по стране отключён – все рабочие серверы попадают в подписку.

import os
import re
import socket
import ssl
import base64
import logging
import subprocess
import time
import json
import tempfile
import sys
import random
import threading
import gzip
import shutil
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from datetime import datetime, timedelta

# =============================================================================
# НАСТРОЙКИ (можно изменять)
# =============================================================================

# ---------- Общие настройки ----------
SOURCES_FILE = "sources.txt"
OUTPUT_FILE = "subscription.txt"
OUTPUT_BASE64_FILE = "subscription_base64.txt"
REQUEST_TIMEOUT = 10
SING_BOX_PATH = "./sing-box"

# ---------- Настройки подписки ----------
PROFILE_TITLE = "🇷🇺КРОТовые ТОННЕЛИ🇷🇺"
SUPPORT_URL = "🇷🇺КРОТовые ТОННЕЛИ🇷🇺"
PROFILE_WEB_PAGE_URL = "🇷🇺КРОТовые ТОННЕЛИ🇷🇺"
PROFILE_UPDATE_INTERVAL = "1"
SUBSCRIPTION_USERINFO = "upload=0; download=0; total=0; expire=0"

# ---------- TCP-проверка ----------
TCP_CHECK_TIMEOUT = 10
TCP_MAX_WORKERS = 400
MAX_LATENCY_MS = 250

# ---------- TLS-проверка ----------
TLS_CHECK_TIMEOUT = 0.5
TLS_MAX_WORKERS = 100

# ---------- Реальная проверка через sing-box ----------
SOCKS_BASE_PORT = 10000
SOCKS_PORT_RANGE = 1000
REAL_CHECK_TIMEOUT = 30
REAL_CHECK_CONCURRENCY = 50
SING_BOX_STARTUP_DELAY = 7

# ---------- Тестовые URL ----------
FAST_TEST_URLS = [
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://www.gstatic.com/generate_204"
]
REAL_SITES = [
    "https://www.google.com/generate_204",
    "https://telegram.org/",
    "https://www.youtube.com/"
]

# ---------- Геоданные (MaxMind) ----------
GEOIP_DB_DIR = "GeoIP"                        # папка для хранения базы
GEOIP_DB_FILENAME = "GeoLite2-City.mmdb"      # имя файла базы
GEOIP_DB_PATH = os.path.join(GEOIP_DB_DIR, GEOIP_DB_FILENAME)
GEOIP_DB_URL = "https://cdn.jsdelivr.net/npm/geolite2-city/GeoLite2-City.mmdb.gz"
GEOIP_MAX_AGE_DAYS = 7   # обновлять раз в неделю

# =============================================================================
# КОНЕЦ НАСТРОЕК
# =============================================================================

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
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ---------- РАНДОМНЫЙ USER-AGENT ----------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/121.0 Firefox/121.0"
]

def get_random_ua():
    return random.choice(USER_AGENTS)

# ---------- ДИНАМИЧЕСКИЕ ПОРТЫ ----------
_port_counter = 0
_port_lock = threading.Lock()

def get_next_port():
    global _port_counter
    with _port_lock:
        port = SOCKS_BASE_PORT + (_port_counter % SOCKS_PORT_RANGE)
        _port_counter += 1
        return port

# ---------- ГЕОЛОКАЦИЯ (MAXMIND) ----------
def ensure_geoip_db():
    """Проверяет наличие и свежесть базы GeoIP, при необходимости скачивает в папку GEOIP_DB_DIR."""
    # Создаём папку, если её нет
    os.makedirs(GEOIP_DB_DIR, exist_ok=True)

    if os.path.exists(GEOIP_DB_PATH):
        # Проверяем возраст файла
        mtime = datetime.fromtimestamp(os.path.getmtime(GEOIP_DB_PATH))
        if datetime.now() - mtime < timedelta(days=GEOIP_MAX_AGE_DAYS):
            logging.info(f"🌍 База GeoIP найдена (возраст < {GEOIP_MAX_AGE_DAYS} дней)")
            return True
        else:
            logging.info("🌍 База GeoIP устарела, скачиваю новую...")
    else:
        logging.info("🌍 База GeoIP не найдена, скачиваю...")

    try:
        headers = {'User-Agent': get_random_ua()}
        resp = requests.get(GEOIP_DB_URL, timeout=30, headers=headers)
        resp.raise_for_status()

        # Сохраняем сжатый файл
        gz_path = GEOIP_DB_PATH + ".gz"
        with open(gz_path, 'wb') as f:
            f.write(resp.content)

        # Распаковываем
        with gzip.open(gz_path, 'rb') as f_in:
            with open(GEOIP_DB_PATH, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

        os.remove(gz_path)
        logging.info(f"✅ База GeoIP успешно загружена и распакована в {GEOIP_DB_PATH}")
        return True
    except Exception as e:
        logging.error(f"❌ Ошибка загрузки GeoIP: {e}")
        return False

# Инициализация reader (отложенная, так как база может понадобиться только после проверок)
reader = None

def init_geoip():
    global reader
    if ensure_geoip_db():
        try:
            import geoip2.database
            reader = geoip2.database.Reader(GEOIP_DB_PATH)
            logging.info("✅ GeoIP reader инициализирован")
            return True
        except Exception as e:
            logging.error(f"❌ Не удалось открыть базу GeoIP: {e}")
            return False
    else:
        logging.warning("⚠️ GeoIP недоступен, флаги и города не будут добавлены")
        return False

def get_geo_info(ip):
    """Возвращает (флаг, город, код страны) или (None, None, None) при ошибке."""
    if reader is None:
        return None, None, None
    try:
        response = reader.city(ip)
        country_code = response.country.iso_code
        city = response.city.name if response.city.name else ""
        if country_code:
            # Преобразуем код страны в эмодзи флага
            flag = ''.join(chr(127397 + ord(c)) for c in country_code.upper())
            return flag, city, country_code
        else:
            return None, None, None
    except Exception:
        return None, None, None

# ---------- ВСПОМОГАТЕЛЬНЫЕ ----------
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
        headers = {'User-Agent': get_random_ua()}
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
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

# ---------- ПАРСЕРЫ (без изменений) ----------
def parse_vless_link(link):
    try:
        without_proto = link[8:]
        at_index = without_proto.find('@')
        if at_index == -1:
            return None
        uuid = without_proto[:at_index]
        rest = without_proto[at_index+1:]
        parsed = urlparse(f"tcp://{rest}")
        host = parsed.hostname
        port = parsed.port or 443
        params = parse_qs(parsed.query)
        security = params.get('security', ['none'])[0]
        if security == 'tsl':
            security = 'tls'
        explicit_sni = params.get('sni', [None])[0]
        return {
            'protocol': 'vless',
            'uuid': uuid,
            'host': host,
            'port': port,
            'security': security,
            'encryption': params.get('encryption', ['none'])[0],
            'type': params.get('type', ['tcp'])[0],
            'sni': explicit_sni if explicit_sni else host,
            'explicit_sni': explicit_sni,
            'fp': params.get('fp', ['chrome'])[0],
            'pbk': params.get('pbk', [''])[0],
            'sid': params.get('sid', [''])[0],
            'spx': params.get('spx', ['/'])[0],
            'flow': params.get('flow', [''])[0],
            'path': params.get('path', ['/'])[0],
            'host_header': params.get('host', [host])[0]
        }
    except Exception as e:
        logging.debug(f"Ошибка парсинга Vless: {e}")
        return None

def parse_ss_link(link):
    try:
        rest = link[5:]
        if '#' in rest:
            rest, _ = rest.split('#', 1)
        if '?' in rest:
            rest, _ = rest.split('?', 1)
        if '@' in rest:
            userinfo, hostport = rest.split('@', 1)
            if ':' in userinfo:
                method, password = userinfo.split(':', 1)
            else:
                return None
        else:
            try:
                decoded = base64.b64decode(rest).decode('utf-8')
                if '@' in decoded:
                    userinfo, hostport = decoded.split('@', 1)
                    if ':' in userinfo:
                        method, password = userinfo.split(':', 1)
                    else:
                        return None
                else:
                    return None
            except:
                return None
        if ':' in hostport:
            host, port_str = hostport.rsplit(':', 1)
            port = int(port_str)
        else:
            port = 443
        return {
            'protocol': 'ss',
            'host': host,
            'port': port,
            'method': method,
            'password': password,
            'original': link,
            'explicit_sni': None
        }
    except Exception as e:
        logging.debug(f"Ошибка парсинга SS: {e}")
        return None

def parse_trojan_link(link):
    try:
        parsed = urlparse(link)
        if parsed.scheme != 'trojan':
            return None
        password = parsed.username
        if not password:
            return None
        host = parsed.hostname
        port = parsed.port or 443
        params = parse_qs(parsed.query)
        peer_param = params.get('peer')
        sni_param = params.get('sni')
        explicit_sni = None
        if peer_param:
            explicit_sni = peer_param[0]
        elif sni_param:
            explicit_sni = sni_param[0]
        sni = explicit_sni if explicit_sni else host
        allow_insecure = params.get('allowInsecure', ['0'])[0].lower() in ('1', 'true', 'yes')
        network = params.get('type', ['tcp'])[0]
        security = params.get('security', ['tls'])[0]
        return {
            'protocol': 'trojan',
            'host': host,
            'port': port,
            'password': password,
            'sni': sni,
            'explicit_sni': explicit_sni,
            'allow_insecure': allow_insecure,
            'network': network,
            'security': security,
            'original': link
        }
    except Exception as e:
        logging.debug(f"Ошибка парсинга Trojan: {e}")
        return None

def parse_vmess_link(link):
    try:
        b64_part = link[8:]
        if '#' in b64_part:
            b64_part = b64_part.split('#')[0]
        decoded = base64.b64decode(b64_part).decode('utf-8')
        cfg = json.loads(decoded)
        host = cfg.get('add')
        if not host:
            return None
        port = int(cfg.get('port', 443))
        uuid = cfg.get('id')
        if not uuid:
            return None
        security = cfg.get('scy', 'auto')
        network = cfg.get('net', 'tcp')
        path = cfg.get('path', '/')
        host_header = cfg.get('host', host)
        tls = cfg.get('tls') == 'tls'
        sni = cfg.get('peer') or host_header or host
        return {
            'protocol': 'vmess',
            'host': host,
            'port': port,
            'uuid': uuid,
            'security': security,
            'type': network,
            'path': path,
            'host_header': host_header,
            'tls': tls,
            'sni': sni,
            'explicit_sni': cfg.get('peer'),
            'allow_insecure': cfg.get('allowInsecure', False)
        }
    except Exception as e:
        logging.debug(f"Ошибка парсинга VMess: {e}")
        return None

def parse_hysteria2_link(link):
    try:
        if link.startswith('hysteria2://'):
            rest = link[12:]
        elif link.startswith('hy2://'):
            rest = link[6:]
        else:
            return None

        userinfo = None
        hostport = rest
        if '@' in rest:
            userinfo, hostport = rest.split('@', 1)

        password = None
        if userinfo:
            password = userinfo

        parsed = urlparse(f"//{hostport}")
        host = parsed.hostname
        port = parsed.port or 443
        params = parse_qs(parsed.query)

        insecure = params.get('insecure', ['0'])[0].lower() in ('1', 'true', 'yes')
        sni = params.get('sni', [host])[0]
        up = params.get('up', [''])[0]
        down = params.get('down', [''])[0]
        obfs = params.get('obfs', [''])[0]

        return {
            'protocol': 'hysteria2',
            'host': host,
            'port': port,
            'password': password,
            'sni': sni,
            'explicit_sni': sni if sni != host else None,
            'allow_insecure': insecure,
            'up': up,
            'down': down,
            'obfs': obfs
        }
    except Exception as e:
        logging.debug(f"Ошибка парсинга Hysteria2: {e}")
        return None

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

# ---------- TLS ПРОВЕРКА ----------
def check_tls(host, port, sni=None, timeout=TLS_CHECK_TIMEOUT):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=sni or host) as ssock:
                ssock.do_handshake()
        return True
    except Exception:
        return False

def needs_tls_check(parsed):
    if parsed['protocol'] in ('ss',):
        return False
    if parsed['protocol'] == 'vmess':
        return parsed.get('tls', False)
    if parsed['protocol'] == 'hysteria2':
        return True
    security = parsed.get('security', 'none')
    return security in ('tls', 'reality')

# ---------- СОЗДАНИЕ КОНФИГА SING-BOX ----------
def create_singbox_config(config, socks_port):
    protocol = config['protocol']
    outbound = {
        "tag": "proxy",
        "server": config['host'],
        "server_port": config['port']
    }

    if protocol == 'ss':
        outbound["type"] = "shadowsocks"
        outbound["method"] = config['method']
        outbound["password"] = config['password']

    elif protocol == 'vmess':
        outbound["type"] = "vmess"
        outbound["uuid"] = config['uuid']
        outbound["security"] = config.get('security', 'auto')
        outbound["alter_id"] = 0
        if config.get('type') == 'ws':
            outbound["transport"] = {
                "type": "ws",
                "path": config.get('path', '/'),
                "headers": {"Host": config.get('host_header', config['host'])}
            }
        if config.get('tls'):
            outbound["tls"] = {
                "enabled": True,
                "server_name": config.get('sni', config['host']),
                "utls": {"enabled": True, "fingerprint": config.get('fp', 'chrome')}
            }
        else:
            outbound["tls"] = {"enabled": False}

    elif protocol == 'vless':
        outbound["type"] = "vless"
        outbound["uuid"] = config['uuid']
        outbound["flow"] = config.get('flow', '')
        outbound["packet_encoding"] = "xudp"
        if config.get('type') == 'ws':
            outbound["transport"] = {
                "type": "ws",
                "path": config.get('path', '/'),
                "headers": {"Host": config.get('host_header', config['host'])}
            }
        elif config.get('type') == 'grpc':
            outbound["transport"] = {
                "type": "grpc",
                "service_name": config.get('serviceName', '')
            }
        if config.get('security') in ('tls', 'reality'):
            tls_config = {
                "enabled": True,
                "server_name": config.get('sni', config['host']),
                "utls": {"enabled": True, "fingerprint": config.get('fp', 'chrome')}
            }
            if config.get('security') == 'reality':
                tls_config["reality"] = {
                    "enabled": True,
                    "public_key": config.get('pbk', ''),
                    "short_id": config.get('sid', '')
                }
            outbound["tls"] = tls_config
        else:
            outbound["tls"] = {"enabled": False}

    elif protocol == 'trojan':
        outbound["type"] = "trojan"
        outbound["password"] = config['password']
        if config.get('type') == 'ws':
            outbound["transport"] = {
                "type": "ws",
                "path": config.get('path', '/'),
                "headers": {"Host": config.get('host_header', config['host'])}
            }
        if config.get('security') == 'tls':
            outbound["tls"] = {
                "enabled": True,
                "server_name": config.get('sni', config['host']),
                "utls": {"enabled": True, "fingerprint": config.get('fp', 'chrome')}
            }
        else:
            outbound["tls"] = {"enabled": False}

    elif protocol == 'hysteria2':
        outbound["type"] = "hysteria2"
        outbound["password"] = config['password']
        outbound["tls"] = {
            "enabled": True,
            "server_name": config.get('sni', config['host']),
            "insecure": config.get('allow_insecure', False)
        }
        if config.get('up') or config.get('down'):
            outbound["bandwidth"] = {}
            if config.get('up'):
                outbound["bandwidth"]["up"] = config['up']
            if config.get('down'):
                outbound["bandwidth"]["down"] = config['down']
        if config.get('obfs'):
            outbound["obfs"] = {"type": config['obfs']}

    else:
        return None

    full_config = {
        "log": {"level": "error"},
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": socks_port,
            "users": []
        }],
        "outbounds": [outbound]
    }
    return full_config

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

# ---------- УНИВЕРСАЛЬНАЯ ПРОВЕРКА ЧЕРЕЗ SING-BOX ----------
def check_with_singbox(link, fast_urls, real_urls, fast_timeout=REAL_CHECK_TIMEOUT, real_timeout=REAL_CHECK_TIMEOUT):
    config_dict = parse_link(link)
    if not config_dict:
        return False
    
    socks_port = get_next_port()
    sb_config = create_singbox_config(config_dict, socks_port)
    if not sb_config:
        return False

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config_path = f.name
        json.dump(sb_config, f, indent=2)

    process = None
    try:
        process = subprocess.Popen(
            [SING_BOX_PATH, 'run', '-c', config_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        time.sleep(SING_BOX_STARTUP_DELAY)

        if process.poll() is not None:
            out, err = process.communicate(timeout=1)
            logging.debug(f"sing-box завершился с ошибкой для {shorten_link(link)}: {err}")
            return False

        sock_check = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_check.settimeout(2)
        result = sock_check.connect_ex(('127.0.0.1', socks_port))
        sock_check.close()
        if result != 0:
            logging.debug(f"Порт {socks_port} не открыт для {shorten_link(link)}")
            return False

        proxies = {
            'http': f'socks5h://127.0.0.1:{socks_port}',
            'https': f'socks5h://127.0.0.1:{socks_port}'
        }

        # Проверка быстрых URL
        fast_ok = False
        for url in fast_urls:
            try:
                resp = requests.get(
                    url, proxies=proxies, timeout=fast_timeout,
                    headers={'User-Agent': get_random_ua()}, allow_redirects=False, verify=False
                )
                if resp.status_code in (200, 204):
                    fast_ok = True
                    break
            except Exception:
                continue
        if not fast_ok:
            logging.debug(f"Быстрые URL не открылись для {shorten_link(link)}")
            return False

        # Проверка реальных сайтов (все должны быть доступны, следуем редиректам)
        for url in real_urls:
            try:
                resp = requests.get(
                    url, proxies=proxies, timeout=real_timeout,
                    headers={'User-Agent': get_random_ua()}, allow_redirects=True, verify=False
                )
                if resp.status_code not in (200, 204):
                    logging.debug(f"Реальный сайт {url} вернул код {resp.status_code} для {shorten_link(link)}")
                    return False
            except Exception as e:
                logging.debug(f"Ошибка при запросе реального сайта {url} для {shorten_link(link)}: {e}")
                return False

        return True

    except Exception as e:
        logging.debug(f"Ошибка в check_with_singbox для {link[:60]}: {e}")
        return False
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        if os.path.exists(config_path):
            os.unlink(config_path)

# ---------- ФИЛЬТРАЦИЯ (УЛЬТРА-УСИЛЕННАЯ, 5xTCP, 5xTLS, 1xРеальная на 3 сайта) ----------
def filter_working_links(links):
    global record_counter, current_check, total_checks
    total_checks = len(links)
    logging.info(f"🚀 Начинаю УЛЬТРА-УСИЛЕННУЮ проверку {total_checks} ссылок (TCP x5, TLS x5, реальная x1 на Google, Telegram, YouTube)")

    # ---------- TCP раунды 1-5 ----------
    tcp_current = [(link, None, None) for link in links]  # (link, ip, latency)
    for round_num in range(1, 6):
        if not tcp_current:
            logging.info(f"📊 TCP #{round_num}: нет ссылок для проверки, завершаем.")
            return []
        logging.info(f"🌐 Этап TCP #{round_num}: проверка {len(tcp_current)} ссылок...")
        tcp_next = []
        with ThreadPoolExecutor(max_workers=TCP_MAX_WORKERS) as executor:
            future_to_link = {executor.submit(check_tcp, link): link for link, _, _ in tcp_current}
            for future in as_completed(future_to_link):
                current_check += 1
                link, ok, ip, latency = future.result()
                if ok and ip and latency is not None and latency <= MAX_LATENCY_MS:
                    tcp_next.append((link, ip, latency))
        logging.info(f"📊 TCP #{round_num} завершена. Прошли (latency <= {MAX_LATENCY_MS} мс): {len(tcp_next)}/{len(tcp_current)}")
        tcp_current = tcp_next

    if not tcp_current:
        return []

    # Сохраняем соответствие ссылка -> IP для всех прошедших TCP
    ip_map = {link: ip for link, ip, _ in tcp_current}

    # ---------- TLS раунды 1-5 ----------
    # Сначала парсим все ссылки, прошедшие TCP
    tls_candidates = []
    for link, ip, latency in tcp_current:
        parsed = parse_link(link)
        if parsed:
            tls_candidates.append((link, parsed))
        else:
            logging.debug(f"Не удалось распарсить {shorten_link(link)}, пропускаем")

    if not tls_candidates:
        return []

    tls_current = tls_candidates  # (link, parsed)
    for round_num in range(1, 6):
        if not tls_current:
            logging.info(f"📊 TLS #{round_num}: нет ссылок для проверки, завершаем.")
            return []
        logging.info(f"🔒 Этап TLS #{round_num}: проверка {len(tls_current)} ссылок...")
        tls_next = []
        tls_futures = {}
        tls_processed = 0
        tls_ok = 0
        tls_fail = 0

        with ThreadPoolExecutor(max_workers=TLS_MAX_WORKERS) as executor:
            for link, parsed in tls_current:
                if needs_tls_check(parsed):
                    host = parsed['host']
                    port = parsed['port']
                    sni = parsed.get('sni', host)
                    future = executor.submit(check_tls, host, port, sni)
                    tls_futures[future] = (link, parsed)
                else:
                    tls_next.append((link, parsed))
                    tls_processed += 1
                    tls_ok += 1

            for future in as_completed(tls_futures):
                tls_processed += 1
                link, parsed = tls_futures[future]
                if future.result():
                    tls_next.append((link, parsed))
                    tls_ok += 1
                else:
                    tls_fail += 1
                if tls_processed % 10 == 0:
                    logging.info(f"TLS #{round_num} прогресс: обработано {tls_processed}, OK {tls_ok}, FAIL {tls_fail}")

        logging.info(f"✅ TLS #{round_num} завершена. OK {tls_ok}, FAIL {tls_fail}, всего {tls_processed}")
        tls_current = tls_next

    if not tls_current:
        return []

    # ---------- Реальная проверка (один раунд, 3 сайта) ----------
    logging.info(f"🧪 Этап реальной проверки: {len(tls_current)} ссылок, быстрые URL + Google, Telegram, YouTube...")
    real_working = []  # просто список ссылок
    stage_total = len(tls_current)
    stage_current = 0
    real_ok = 0
    real_fail = 0

    links_to_check = [link for link, _ in tls_current]

    with ThreadPoolExecutor(max_workers=REAL_CHECK_CONCURRENCY) as executor:
        future_to_link = {executor.submit(lambda l: (l, check_with_singbox(l, FAST_TEST_URLS, REAL_SITES)), link): link for link in links_to_check}
        for future in as_completed(future_to_link):
            stage_current += 1
            current_check += 1
            record_counter += 1
            link, is_working = future.result()
            short = shorten_link(link)

            if is_working:
                real_working.append(link)
                real_ok += 1
            else:
                real_fail += 1

            if stage_current % 10 == 0:
                log_msg = f"Реальная проверка прогресс: {stage_current}/{stage_total}, OK {real_ok}, FAIL {real_fail}"
                logging.info(log_msg)

    logging.info(f"📊 Реальная проверка завершена. Прошли: {len(real_working)}/{stage_total}, OK {real_ok}, FAIL {real_fail}")

    if not real_working:
        return []

    # ---------- Геолокация для прошедших реальную проверку ----------
    # Инициализируем GeoIP, если ещё не сделано (ленивая инициализация)
    if reader is None:
        init_geoip()

    logging.info(f"🌍 Получаем геоданные для {len(real_working)} серверов...")
    result_with_geo = []
    for link in real_working:
        ip = ip_map.get(link)
        if ip:
            flag, city, country_code = get_geo_info(ip)
        else:
            flag, city, country_code = None, None, None
        result_with_geo.append((link, flag, city, country_code))

    return result_with_geo

# ---------- СОХРАНЕНИЕ ----------
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
        for idx, (link, flag, city, country_code) in enumerate(links_with_geo, 1):
            link_clean = re.sub(r'#.*$', '', link)
            city_part = f" {city}" if city else ""
            country_flag = flag if flag else (country_code if country_code else "")
            tag = f"#🔑📱ТОННЕЛЬ {idx:04d} | {country_flag}{city_part} |"
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

def check_singbox_available():
    logging.info("🔍 Проверка sing-box...")
    try:
        result = subprocess.run([SING_BOX_PATH, 'version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            logging.info(f"✅ sing-box: {result.stdout.splitlines()[0]}")
            return True
        else:
            logging.warning("⚠️ sing-box не отвечает")
            return False
    except FileNotFoundError:
        logging.error(f"❌ sing-box не найден по пути '{SING_BOX_PATH}'")
        return False
    except Exception as e:
        logging.error(f"❌ Ошибка проверки sing-box: {e}")
        return False

# ---------- ГЛАВНАЯ ----------
def main():
    global record_counter, current_check, total_checks
    logging.info("🟢 Запуск УЛЬТРА-УСИЛЕННОГО генератора подписок (TCP x5, TLS x5, реальная x1 на Google, Telegram, YouTube)")
    if not check_singbox_available():
        logging.error("sing-box обязателен. Завершение.")
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
        logging.warning("Нет рабочих серверов – Base64 не создана.")

    logging.info(f"📊 Итог: {len(working_links_with_geo)} рабочих из {len(all_links)} проверенных")
    logging.info("🏁 Работа завершена")

if __name__ == "__main__":
    main()
