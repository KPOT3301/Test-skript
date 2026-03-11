#!/usr/bin/env python3
# GENERATOR.py – Двухуровневая проверка Vless/SS/Trojan/VMess/Hysteria2 серверов + флаги стран и города
# Ужесточена TCP-проверка: 3 последовательные попытки, таймаут 5 с, макс. задержка 300 мс.
# Фильтрация: только Россия и следующие страны Европы: FI, EE, LV, LT, PL, DE, SE, MD, TR.
# В подписках серверы сортируются по возрастанию задержки (самые быстрые в начале).

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

# ---------- КОНСТАНТЫ ПОДПИСОК ----------
# Российская подписка
RUS_PROFILE_TITLE = "🇷🇺КРОТовыеТОННЕЛИ🇷🇺"
RUS_SUPPORT_URL = "🇷🇺КРОТовыеТОННЕЛИ🇷🇺"
RUS_PROFILE_WEB_PAGE_URL = "🇷🇺КРОТовыеТОННЕЛИ🇷🇺"
# Европейская подписка (только указанные страны)
EUR_PROFILE_TITLE = "🇪🇺КРОТовыеТОННЕЛИ🇪🇺"
EUR_SUPPORT_URL = "🇪🇺КРОТовыеТОННЕЛИ🇪🇺"
EUR_PROFILE_WEB_PAGE_URL = "🇪🇺КРОТовыеТОННЕЛИ🇪🇺"

PROFILE_UPDATE_INTERVAL = "1"
SUBSCRIPTION_USERINFO = "upload=0; download=0; total=0; expire=0"

# ---------- ОСНОВНЫЕ КОНСТАНТЫ ----------
SOURCES_FILE = "sources.txt"
# Выходные файлы для российской подписки
OUTPUT_RUS_FILE = "subscription_RUS.txt"
OUTPUT_RUS_BASE64_FILE = "subscription_RUS_base64.txt"
# Выходные файлы для европейской подписки (выбранные страны)
OUTPUT_EUR_FILE = "subscription_EUR.txt"
OUTPUT_EUR_BASE64_FILE = "subscription_EUR_base64.txt"

REQUEST_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
XRAY_CORE_PATH = "xray"

# TCP-проверка (ужесточена)
TCP_CHECK_TIMEOUT = 5           # было 10
TCP_MAX_WORKERS = 400
MAX_LATENCY_MS = 300             # было 500

# Реальная проверка
SOCKS_PORT = 8080
REAL_CHECK_TIMEOUT = 15
REAL_CHECK_CONCURRENCY = 30
XRAY_STARTUP_DELAY = 1

TEST_URLS = [
    "http://connectivitycheck.gstatic.com/generate_204"
]

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
    """Возвращает (флаг, город, код страны) для указанного IP"""
    if reader is None:
        return "", "", ""
    try:
        response = reader.city(ip)
        country_code = response.country.iso_code
        city = response.city.name if response.city.name else ""
        flag = ''.join(chr(127397 + ord(c)) for c in country_code.upper()) if country_code else ""
        return flag, city, country_code
    except Exception:
        return "", "", ""

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

# ---------- ПАРСЕРЫ ----------
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
        b64_part = link[8:]  # после vmess://
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
    """Возвращает сокращённое представление ссылки: протокол://хост:порт"""
    parsed = parse_link(link)
    if parsed:
        return f"{parsed['protocol']}://{parsed['host']}:{parsed['port']}"
    q_pos = link.find('?')
    if q_pos != -1:
        return link[:q_pos]
    return link[:80]

# ---------- СОЗДАНИЕ КОНФИГА XRAY ----------
def create_xray_config(config):
    base_config = {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "port": SOCKS_PORT,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}
        }],
        "outbounds": []
    }
    protocol = config['protocol']

    if protocol == 'vless':
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": config['host'],
                    "port": config['port'],
                    "users": [{
                        "id": config['uuid'],
                        "encryption": config.get('encryption', 'none'),
                        "flow": config.get('flow', '')
                    }]
                }]
            },
            "streamSettings": {
                "network": config.get('type', 'tcp'),
                "security": config.get('security', 'none')
            }
        }
        if config['security'] == 'tls':
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": config.get('sni', config['host']),
                "fingerprint": config.get('fp', 'chrome'),
                "allowInsecure": False
            }
        elif config['security'] == 'reality':
            outbound["streamSettings"]["realitySettings"] = {
                "serverName": config.get('sni', config['host']),
                "fingerprint": config.get('fp', 'random'),
                "publicKey": config.get('pbk', ''),
                "shortId": config.get('sid', ''),
                "spiderX": config.get('spx', '/')
            }
        if config.get('type') == 'ws':
            outbound["streamSettings"]["wsSettings"] = {
                "path": config.get('path', '/'),
                "headers": {"Host": config.get('host_header', config['host'])}
            }

    elif protocol == 'vmess':
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": config['host'],
                    "port": config['port'],
                    "users": [{
                        "id": config['uuid'],
                        "security": config.get('security', 'auto')
                    }]
                }]
            },
            "streamSettings": {
                "network": config.get('type', 'tcp'),
                "security": config.get('tls', False) and "tls" or "none"
            }
        }
        if config.get('tls'):
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": config.get('sni', config['host']),
                "allowInsecure": config.get('allow_insecure', False)
            }
        if config.get('type') == 'ws':
            outbound["streamSettings"]["wsSettings"] = {
                "path": config.get('path', '/'),
                "headers": {"Host": config.get('host_header', config['host'])}
            }

    elif protocol == 'ss':
        outbound = {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": config['host'],
                    "port": config['port'],
                    "method": config['method'],
                    "password": config['password']
                }]
            },
            "streamSettings": {"network": "tcp", "security": "none"}
        }

    elif protocol == 'trojan':
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": config['host'],
                    "port": config['port'],
                    "password": config['password']
                }]
            },
            "streamSettings": {
                "network": config.get('network', 'tcp'),
                "security": config.get('security', 'tls')
            }
        }
        if config.get('security') == 'tls':
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": config.get('sni', config['host']),
                "allowInsecure": config.get('allow_insecure', False)
            }

    elif protocol == 'hysteria2':
        outbound = {
            "protocol": "hysteria2",
            "settings": {
                "server": config['host'],
                "port": config['port'],
                "password": config['password'],
                "tls": {
                    "sni": config.get('sni', config['host']),
                    "insecure": config.get('allow_insecure', False)
                }
            }
        }
        if config.get('up') or config.get('down'):
            outbound["settings"]["bandwidth"] = {}
            if config.get('up'):
                outbound["settings"]["bandwidth"]["up"] = config['up']
            if config.get('down'):
                outbound["settings"]["bandwidth"]["down"] = config['down']
        if config.get('obfs'):
            outbound["settings"]["obfs"] = config['obfs']

    else:
        return None

    base_config["outbounds"].append(outbound)
    return base_config

# ---------- TCP ПРОВЕРКА (3 попытки) ----------
def check_tcp(link):
    parsed = parse_link(link)
    if not parsed:
        return (link, False, None, None)
    host, port = parsed['host'], parsed['port']
    try:
        ip = resolve_host(host)
        latencies = []
        for attempt in range(3):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TCP_CHECK_TIMEOUT)
            start = time.time()
            result = sock.connect_ex((ip, port))
            latency_ms = int((time.time() - start) * 1000) if result == 0 else None
            sock.close()
            if result != 0 or latency_ms is None:
                return (link, False, None, None)
            if latency_ms > MAX_LATENCY_MS:
                return (link, False, None, None)
            latencies.append(latency_ms)
        # Все три попытки успешны и не превышают лимит
        min_latency = min(latencies)
        return (link, True, ip, min_latency)
    except:
        return (link, False, None, None)

# ---------- РЕАЛЬНАЯ ПРОВЕРКА (однократная, без повторов) ----------
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

        # Определяем, нужно ли проверять HTTPS (для TLS-ключей)
        needs_https = False
        if config_dict['protocol'] in ('vless', 'vmess', 'trojan', 'hysteria2'):
            if config_dict['protocol'] == 'vmess':
                needs_https = config_dict.get('tls', False)
            elif config_dict['protocol'] == 'hysteria2':
                needs_https = True
            else:
                security = config_dict.get('security', 'none')
                if security in ('tls', 'reality'):
                    needs_https = True

        # Однократная HTTP-проверка (перебираем тестовые URL, пока один не сработает)
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
            return (link, False)

        # Однократная дополнительная проверка HTTPS (если нужна)
        if needs_https:
            try:
                https_test = "https://www.google.com/generate_204"
                requests.get(https_test, proxies=proxies, timeout=REAL_CHECK_TIMEOUT,
                             headers={'User-Agent': USER_AGENT}, verify=False)
                # если дошли до сюда – успех
            except Exception:
                return (link, False)

        # Все проверки пройдены
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

# ---------- ДВУХУРОВНЕВАЯ ФИЛЬТРАЦИЯ С ОТСЕВОМ ПО TCP-ЗАДЕРЖКЕ ----------
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
                # Отсев по задержке уже выполнен внутри check_tcp (все три попытки успешны и <= MAX_LATENCY_MS)
                tcp_success.append((link, ip, latency))
    logging.info(f"📊 TCP-проверка завершена. Прошли (3 успешные попытки, latency <= {MAX_LATENCY_MS} мс): {len(tcp_success)}/{total_checks}")

    if not tcp_success:
        return []

    # Определяем флаги и города для прошедших TCP
    logging.info(f"🌍 Определение геоданных для {len(tcp_success)} серверов...")
    candidates = []  # (link, flag, city, country_code, latency)
    for link, ip, latency in tcp_success:
        flag, city, country_code = get_geo_info(ip) if ip else ("", "", "")
        if flag:
            candidates.append((link, flag, city, country_code, latency))

    logging.info(f"🧾 Серверов с флагами: {len(candidates)}")

    # Фильтр: только Россия и Европа (полный список европейских стран)
    european_countries = {
        'RU', 'AL', 'AD', 'AT', 'BY', 'BE', 'BA', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE',
        'FI', 'FR', 'DE', 'GR', 'HU', 'IS', 'IE', 'IT', 'LV', 'LI', 'LT', 'LU',
        'MT', 'MD', 'MC', 'ME', 'NL', 'MK', 'NO', 'PL', 'PT', 'RO', 'SM', 'RS',
        'SK', 'SI', 'ES', 'SE', 'CH', 'UA', 'GB', 'VA', 'TR'
    }
    filtered_candidates = [
        item for item in candidates if item[3] in european_countries
    ]
    logging.info(f"🌍 Российских и европейских (все страны): {len(filtered_candidates)}")

    if not filtered_candidates:
        return []

    # Словарь для быстрого доступа к информации о кандидате по ссылке
    candidate_info = {item[0]: item[1:] for item in filtered_candidates}  # link -> (flag, city, country_code, latency)

    # Этап 2: реальная проверка только для filtered_candidates
    logging.info(f"🧪 Этап 2: Реальная проверка {len(filtered_candidates)} ссылок...")
    working_links_with_geo = []  # (link, flag, city, country_code, latency)
    stage_total = len(filtered_candidates)
    stage_current = 0

    links_to_check = [item[0] for item in filtered_candidates]

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

            flag, city, country_code, latency = candidate_info[link]

            if is_working:
                working_links_with_geo.append((link, flag, city, country_code, latency))
                emoji = "✅"
            else:
                emoji = "❌"

            log_msg = f"{proto} {emoji} [{stage_current}/{stage_total}]: {short} (latency={latency}ms)"
            logging.info(log_msg)

    logging.info(f"📊 Реальная проверка завершена. Рабочих с флагами: {len(working_links_with_geo)}/{stage_total}")
    return working_links_with_geo

# ---------- СОХРАНЕНИЕ РЕЗУЛЬТАТОВ ДЛЯ ГРУППЫ (РОССИЯ ИЛИ ВЫБРАННЫЕ ЕВРОПЕЙСКИЕ) ----------
def save_working_links_group(links_with_geo, filename, title, support_url, web_page_url):
    """
    Сохраняет список серверов в файл с заданными заголовками подписки.
    links_with_geo: список кортежей (link, flag, city, country_code, latency)
    latency используется только для сортировки (самые быстрые в начале)
    """
    if not links_with_geo:
        logging.warning(f"⚠️ Нет серверов для сохранения в {filename}")
        return 0

    # Сортируем по возрастанию задержки (самые быстрые первые)
    sorted_links = sorted(links_with_geo, key=lambda x: x[4])  # x[4] — latency

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"#profile-title:{title}\n")
        f.write(f"#subscription-userinfo:{SUBSCRIPTION_USERINFO}\n")
        f.write(f"#profile-update-interval:{PROFILE_UPDATE_INTERVAL}\n")
        f.write(f"#support-url:{support_url}\n")
        f.write(f"#profile-web-page-url:{web_page_url}\n")
        f.write(f"#announce: АКТИВНЫХ ТОННЕЛЕЙ 🚀 {len(sorted_links)} | ОБНОВЛЕНО 📅 {TODAY_STR}\n")
        for idx, (link, flag, city, _, _) in enumerate(sorted_links, 1):
            link_clean = re.sub(r'#.*$', '', link)
            city_part = f" {city}" if city else ""
            tag = f"#🔑📱ТОННЕЛЬ {idx:04d} | {flag}{city_part} |"
            f.write(link_clean + tag + '\n')

    logging.info(f"✅ Сохранено {len(sorted_links)} серверов в {filename}")
    return len(sorted_links)

def create_base64_subscription_for_file(input_file, output_file):
    """Создаёт base64-версию указанного файла подписки."""
    try:
        with open(input_file, 'rb') as f:
            encoded = base64.b64encode(f.read()).decode('ascii')
        with open(output_file, 'w', encoding='ascii') as f:
            f.write(encoded)
        logging.info(f"💾 Base64-версия сохранена в {output_file}")
    except Exception as e:
        logging.error(f"❌ Ошибка создания Base64 для {input_file}: {e}")

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
    logging.info("🟢 Запуск генератора подписок (протоколы: Vless, SS, Trojan, VMess, Hysteria2; TCP-таймаут=5с, 3 попытки, макс. задержка=300мс)")
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

    # Множество стран, которые попадают в европейскую подписку
    allowed_eur_countries = {'FI', 'EE', 'LV', 'LT', 'PL', 'DE', 'SE', 'MD', 'TR'}

    rus_links = []
    eur_links = []
    for item in working_links_with_geo:  # item = (link, flag, city, country_code, latency)
        cc = item[3]
        if cc == 'RU':
            rus_links.append(item)
        elif cc in allowed_eur_countries:
            eur_links.append(item)
        # else: пропускаем

    logging.info(f"🇷🇺 Российских серверов: {len(rus_links)}")
    logging.info(f"🇪🇺 Европейских (FI, EE, LV, LT, PL, DE, SE, MD, TR) серверов: {len(eur_links)}")

    # Сохраняем российскую подписку
    written_rus = save_working_links_group(
        rus_links,
        OUTPUT_RUS_FILE,
        RUS_PROFILE_TITLE,
        RUS_SUPPORT_URL,
        RUS_PROFILE_WEB_PAGE_URL
    )
    if written_rus > 0:
        create_base64_subscription_for_file(OUTPUT_RUS_FILE, OUTPUT_RUS_BASE64_FILE)

    # Сохраняем европейскую подписку
    written_eur = save_working_links_group(
        eur_links,
        OUTPUT_EUR_FILE,
        EUR_PROFILE_TITLE,
        EUR_SUPPORT_URL,
        EUR_PROFILE_WEB_PAGE_URL
    )
    if written_eur > 0:
        create_base64_subscription_for_file(OUTPUT_EUR_FILE, OUTPUT_EUR_BASE64_FILE)

    total_saved = written_rus + written_eur
    logging.info(f"📊 Итог: всего рабочих с флагами: {len(working_links_with_geo)} из {len(all_links)} проверенных, сохранено: {total_saved}")
    logging.info("🏁 Работа завершена")

if __name__ == "__main__":
    main()
