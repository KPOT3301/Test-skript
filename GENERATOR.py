#!/usr/bin/env python3
# GENERATOR.py – Двухуровневая проверка Vless/SS/Trojan/VMess/Hysteria2 серверов + флаги стран и города
# Все основные настройки вынесены в начало для удобства.
# Добавлен случайный выбор User-Agent из списка популярных.
# Добавлена статистика по источникам: сколько ссылок получено из каждого.
# На этапе TCP-проверки добавлена проверка наличия explicit SNI (ключи без SNI отбрасываются).
# Дедупликация по IP выполняется перед реальной проверкой (остаётся сервер с наименьшей задержкой).
# Замер времени HTTP/HTTPS запросов и отсев медленных.
# Расширен список тестовых URL.
# В announce используется только дата (без секунд) для меньшего числа коммитов.
# ИЗМЕНЕНИЕ: убрана проверка наличия флага – все серверы, прошедшие TCP, участвуют в реальной проверке.

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
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from datetime import datetime

# Отключаем предупреждения urllib3 о неверифицированных HTTPS запросах
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.getLogger("urllib3").setLevel(logging.ERROR)

# ---------- НАСТРОЙКА ЛОГИРОВАНИЯ ----------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)],
    force=True
)

# ---------- ГЛОБАЛЬНЫЕ СЧЁТЧИКИ ----------
record_counter = 0
current_check = 0
total_checks = 0

# ---------- ЧАСОВОЙ ПОЯС ----------
try:
    from zoneinfo import ZoneInfo
    TIMEZONE = "Asia/Yekaterinburg"
    LOCAL_NOW = datetime.now(ZoneInfo(TIMEZONE))
except ImportError:
    LOCAL_NOW = datetime.utcnow()
TODAY_STR = LOCAL_NOW.strftime("%d-%m-%Y")

import requests

# =============================================================================
#                          НАСТРАИВАЕМЫЕ КОНСТАНТЫ
# =============================================================================

# ---------- GeoIP ----------
GEOIP_AVAILABLE = False
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    pass

GEOIP_DB_PATH = "GeoLite2-City.mmdb"
GEOIP_DB_URL = "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb"

# ---------- Заголовки подписок ----------
RUS_PROFILE_TITLE = "🇷🇺КРОТовыеТОННЕЛИ🇷🇺"
RUS_SUPPORT_URL = "🇷🇺КРОТовыеТОННЕЛИ🇷🇺"
RUS_PROFILE_WEB_PAGE_URL = "🇷🇺КРОТовыеТОННЕЛИ🇷🇺"
OTHER_PROFILE_TITLE = "🌍КРОТовыеТОННЕЛИ🌍"
OTHER_SUPPORT_URL = "🌍КРОТовыеТОННЕЛИ🌍"
OTHER_PROFILE_WEB_PAGE_URL = "🌍КРОТовыеТОННЕЛИ🌍"

PROFILE_UPDATE_INTERVAL = "1"
SUBSCRIPTION_USERINFO = "upload=0; download=0; total=0; expire=0"

# ---------- Входные / выходные файлы ----------
SOURCES_FILE = "sources.txt"
OUTPUT_RUS_FILE = "subscription_RUS.txt"
OUTPUT_RUS_BASE64_FILE = "subscription_RUS_base64.txt"
OUTPUT_OTHER_FILE = "subscription_OTHER.txt"
OUTPUT_OTHER_BASE64_FILE = "subscription_OTHER_base64.txt"

# ---------- Общие сетевые настройки ----------
REQUEST_TIMEOUT = 10
XRAY_CORE_PATH = "xray"

# ---------- Список User-Agent для случайного выбора ----------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
]

# ---------- TCP-проверка (этап 1) ----------
TCP_CHECK_TIMEOUT = 5           # таймаут соединения, секунд
TCP_MAX_WORKERS = 400            # количество параллельных потоков
MAX_LATENCY_MS = 300             # максимальная допустимая TCP-задержка (мс)
TCP_ATTEMPTS = 3                 # количество попыток TCP-соединения

# ---------- Реальная проверка через Xray (этап 2) ----------
REAL_CHECK_TIMEOUT = 15          # таймаут HTTP/HTTPS запросов (секунд)
REAL_CHECK_CONCURRENCY = 20       # параллельных проверок Xray
REAL_CHECK_ATTEMPTS = 1           # количество попыток реальной проверки
MAX_HTTP_LATENCY_MS = 1000        # максимальная задержка HTTP (мс) – отсев медленных

# ---------- Тестовые URL для проверки ----------
TEST_HTTP_URLS = [
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://www.msftncsi.com/ncsi.txt",
    "http://detectportal.firefox.com/success.txt",
    "http://cp.cloudflare.com/generate_204",
    "http://clients3.google.com/generate_204",
    "http://connect.rom.miui.com/generate_204"
]

TEST_HTTPS_URLS = [
    "https://www.google.com/generate_204",
    "https://cloudflare.com/cdn-cgi/trace",
    "https://cp.cloudflare.com/generate_204"
]

# ---------- DNS-over-HTTPS проверка ----------
DOH_URL = "https://1.1.1.1/dns-query?name=google.com&type=A"
DOH_HEADERS = {"Accept": "application/dns-json"}

# ---------- Диапазон локальных портов для SOCKS (динамическое выделение) ----------
SOCKS_PORT_START = 10000
SOCKS_PORT_END = 11000

# =============================================================================
#                          КОНЕЦ НАСТРОЕК
# =============================================================================

# ---------- Загрузка GeoIP (если доступно) ----------
reader = None
if GEOIP_AVAILABLE:
    if not os.path.exists(GEOIP_DB_PATH):
        try:
            r = requests.get(GEOIP_DB_URL, timeout=30, headers={'User-Agent': random.choice(USER_AGENTS)})
            r.raise_for_status()
            with open(GEOIP_DB_PATH, 'wb') as f:
                f.write(r.content)
        except Exception:
            pass
    try:
        reader = geoip2.database.Reader(GEOIP_DB_PATH)
    except Exception:
        pass

def get_geo_info(ip):
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

# ---------- Вспомогательные функции ----------
@lru_cache(maxsize=256)
def resolve_host(host):
    return socket.gethostbyname(host)

def find_free_port():
    for _ in range(10):
        port = random.randint(SOCKS_PORT_START, SOCKS_PORT_END)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('', port))
                return port
            except OSError:
                continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def read_sources():
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
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={'User-Agent': random.choice(USER_AGENTS)})
        resp.raise_for_status()
        return resp.text
    except Exception:
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
    all_links = set()
    source_stats = []  # список кортежей (источник, количество ссылок)
    for idx, src in enumerate(sources, 1):
        if src.startswith(('vless://', 'ss://', 'trojan://', 'vmess://', 'hysteria2://', 'hy2://')):
            all_links.add(src)
            source_stats.append((src[:60], 1))
            continue
        content = fetch_content(src)
        if not content:
            source_stats.append((src[:60], 0))
            continue
        decoded = decode_base64_content(content)
        links = extract_links_from_text(content)
        if decoded != content:
            links.extend(extract_links_from_text(decoded))
        unique_from_source = set(links)
        for link in unique_from_source:
            all_links.add(link)
        source_stats.append((src[:60], len(unique_from_source)))
        logging.info(f"🔗 [{idx}/{len(sources)}] {src[:60]}... получено {len(unique_from_source)} ссылок")
    logging.info("📊 Статистика по источникам:")
    for src, cnt in source_stats:
        logging.info(f"   {src}: {cnt} ссылок")
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
    except Exception:
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
    except Exception:
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
    except Exception:
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
    except Exception:
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
    except Exception:
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

# ---------- СОЗДАНИЕ КОНФИГА XRAY ----------
def create_xray_config(config, socks_port):
    base_config = {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "port": socks_port,
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

# ---------- TCP ПРОВЕРКА (3 попытки + проверка наличия SNI и его разрешимости) ----------
def check_tcp(link):
    parsed = parse_link(link)
    if not parsed:
        return (link, False, None, None)
    host, port = parsed['host'], parsed['port']
    explicit_sni = parsed.get('explicit_sni')
    # Если нет явного SNI, считаем ключ нерабочим
    if explicit_sni is None:
        return (link, False, None, None)
    try:
        ip = resolve_host(host)
        # Проверка разрешимости explicit_sni (если это домен)
        if re.search(r'[a-zA-Z]', explicit_sni):
            try:
                resolve_host(explicit_sni)
            except socket.gaierror:
                return (link, False, None, None)
        latencies = []
        for _ in range(TCP_ATTEMPTS):
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
        return (link, True, ip, min(latencies))
    except:
        return (link, False, None, None)

# ---------- РЕАЛЬНАЯ ПРОВЕРКА (одна попытка) с замером времени ----------
def check_real(link):
    config_dict = parse_link(link)
    if not config_dict:
        return (link, False)
    
    socks_port = find_free_port()
    xray_config = create_xray_config(config_dict, socks_port)
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
        time.sleep(1)
        proxies = {
            'http': f'socks5h://127.0.0.1:{socks_port}',
            'https': f'socks5h://127.0.0.1:{socks_port}'
        }

        # Определяем, нужна ли HTTPS-проверка
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

        def single_check():
            start_total = time.time()
            # HTTP
            http_ok = False
            for url in TEST_HTTP_URLS:
                try:
                    start = time.time()
                    requests.get(
                        url, proxies=proxies, timeout=REAL_CHECK_TIMEOUT,
                        headers={'User-Agent': random.choice(USER_AGENTS)}, allow_redirects=False
                    )
                    latency = int((time.time() - start) * 1000)
                    if latency > MAX_HTTP_LATENCY_MS:
                        return False
                    http_ok = True
                    break
                except Exception:
                    continue
            if not http_ok:
                return False

            # HTTPS (если нужен)
            if needs_https:
                https_ok = False
                for url in TEST_HTTPS_URLS:
                    try:
                        start = time.time()
                        requests.get(
                            url, proxies=proxies, timeout=REAL_CHECK_TIMEOUT,
                            headers={'User-Agent': random.choice(USER_AGENTS)}, verify=False
                        )
                        latency = int((time.time() - start) * 1000)
                        if latency > MAX_HTTP_LATENCY_MS:
                            return False
                        https_ok = True
                        break
                    except Exception:
                        continue
                if not https_ok:
                    return False

            # DNS через DoH
            try:
                start = time.time()
                resp = requests.get(
                    DOH_URL, proxies=proxies, timeout=REAL_CHECK_TIMEOUT,
                    headers={'User-Agent': random.choice(USER_AGENTS), **DOH_HEADERS}, verify=False
                )
                latency = int((time.time() - start) * 1000)
                if latency > MAX_HTTP_LATENCY_MS:
                    return False
                data = resp.json()
                if 'Answer' not in data or len(data['Answer']) == 0:
                    return False
            except Exception:
                return False

            total_latency = int((time.time() - start_total) * 1000)
            if total_latency > MAX_HTTP_LATENCY_MS * 3:
                return False
            return True

        # Выполняем REAL_CHECK_ATTEMPTS попыток
        for attempt in range(REAL_CHECK_ATTEMPTS):
            if not single_check():
                return (link, False)
            if attempt < REAL_CHECK_ATTEMPTS - 1:
                time.sleep(0.5)

        return (link, True)

    except Exception:
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
    logging.info(f"🌐 Этап 1: TCP-проверка {total_checks} ссылок...")
    
    # Этап 1: TCP
    tcp_success = []  # (link, ip, latency)
    with ThreadPoolExecutor(max_workers=TCP_MAX_WORKERS) as executor:
        future_to_link = {executor.submit(check_tcp, link): link for link in links}
        for future in as_completed(future_to_link):
            current_check += 1
            link, ok, ip, latency = future.result()
            if ok:
                tcp_success.append((link, ip, latency))

    logging.info(f"📊 TCP-проверка завершена. Прошли: {len(tcp_success)}/{total_checks}")

    if not tcp_success:
        return []

    # Геоданные – теперь добавляем все серверы, даже если флаг не определён
    candidates = []  # (link, flag, city, country_code, latency, ip)
    for link, ip, latency in tcp_success:
        flag, city, country_code = get_geo_info(ip) if ip else ("", "", "")
        candidates.append((link, flag, city, country_code, latency, ip))

    logging.info(f"🧾 Серверов после TCP: {len(candidates)}")

    if not candidates:
        return []

    # ----- ДЕДУПЛИКАЦИЯ ПО IP ПЕРЕД РЕАЛЬНОЙ ПРОВЕРКОЙ -----
    best_by_ip = {}
    for cand in candidates:
        link, flag, city, country_code, latency, ip = cand
        if ip not in best_by_ip or latency < best_by_ip[ip][4]:
            best_by_ip[ip] = cand
    deduplicated_candidates = list(best_by_ip.values())
    removed = len(candidates) - len(deduplicated_candidates)
    if removed > 0:
        logging.info(f"🗑 Удалено дубликатов по IP перед реальной проверкой: {removed}")

    # Строим словарь для быстрого доступа и список ссылок для проверки
    candidate_info = {c[0]: c[1:] for c in deduplicated_candidates}  # link -> (flag, city, country_code, latency, ip)
    links_to_check = [c[0] for c in deduplicated_candidates]
    total_to_check = len(links_to_check)
    processed = 0

    working_links_with_geo = []  # (link, flag, city, country_code, latency, ip)

    with ThreadPoolExecutor(max_workers=REAL_CHECK_CONCURRENCY) as executor:
        future_to_link = {executor.submit(check_real, link): link for link in links_to_check}
        for future in as_completed(future_to_link):
            processed += 1
            current_check += 1
            record_counter += 1
            link, is_working = future.result()
            short = shorten_link(link)
            proto = link.split('://')[0][:8]
            flag, city, country_code, latency, ip = candidate_info[link]

            if is_working:
                working_links_with_geo.append((link, flag, city, country_code, latency, ip))
                emoji = "✅"
            else:
                emoji = "❌"

            logging.info(f"{proto} {emoji} [{processed}/{total_to_check}]: {short} (tcp_latency={latency}ms)")

    return working_links_with_geo

# ---------- СОХРАНЕНИЕ ----------
def save_working_links_group(links_with_geo, filename, title, support_url, web_page_url):
    if not links_with_geo:
        return 0
    # Сортировка по TCP-задержке (элемент [4] - latency)
    sorted_links = sorted(links_with_geo, key=lambda x: x[4])
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"#profile-title:{title}\n")
        f.write(f"#subscription-userinfo:{SUBSCRIPTION_USERINFO}\n")
        f.write(f"#profile-update-interval:{PROFILE_UPDATE_INTERVAL}\n")
        f.write(f"#support-url:{support_url}\n")
        f.write(f"#profile-web-page-url:{web_page_url}\n")
        f.write(f"#announce: АКТИВНЫХ ТОННЕЛЕЙ 🚀 {len(sorted_links)} | ОБНОВЛЕНО 📅 {TODAY_STR}\n")
        for idx, (link, flag, city, _, _, _) in enumerate(sorted_links, 1):
            link_clean = re.sub(r'#.*$', '', link)
            city_part = f" {city}" if city else ""
            tag = f"#🔑📱ТОННЕЛЬ {idx:04d} | {flag}{city_part} |"
            f.write(link_clean + tag + '\n')
    return len(sorted_links)

def create_base64_subscription_for_file(input_file, output_file):
    try:
        with open(input_file, 'rb') as f:
            encoded = base64.b64encode(f.read()).decode('ascii')
        with open(output_file, 'w', encoding='ascii') as f:
            f.write(encoded)
        logging.info(f"💾 Base64-версия сохранена в {output_file}")
    except Exception as e:
        logging.error(f"❌ Ошибка создания Base64 для {input_file}: {e}")

def check_xray_available():
    try:
        result = subprocess.run([XRAY_CORE_PATH, '--version'], capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except FileNotFoundError:
        logging.error(f"❌ Xray-core не найден по пути '{XRAY_CORE_PATH}'")
        return False
    except Exception:
        return False

# ---------- ГЛАВНАЯ ----------
def main():
    global record_counter, current_check, total_checks
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

    # Разделяем на российские и остальные
    rus_links = [item for item in working_links_with_geo if item[3] == 'RU']
    other_links = [item for item in working_links_with_geo if item[3] != 'RU']

    logging.info(f"🇷🇺 Российских серверов: {len(rus_links)}")
    logging.info(f"🌍 Остальных серверов: {len(other_links)}")

    written_rus = save_working_links_group(
        rus_links, OUTPUT_RUS_FILE, RUS_PROFILE_TITLE, RUS_SUPPORT_URL, RUS_PROFILE_WEB_PAGE_URL
    )
    if written_rus > 0:
        logging.info(f"✅ Сохранено {written_rus} российских серверов в {OUTPUT_RUS_FILE}")
        create_base64_subscription_for_file(OUTPUT_RUS_FILE, OUTPUT_RUS_BASE64_FILE)

    written_other = save_working_links_group(
        other_links, OUTPUT_OTHER_FILE, OTHER_PROFILE_TITLE, OTHER_SUPPORT_URL, OTHER_PROFILE_WEB_PAGE_URL
    )
    if written_other > 0:
        logging.info(f"✅ Сохранено {written_other} серверов других стран в {OUTPUT_OTHER_FILE}")
        create_base64_subscription_for_file(OUTPUT_OTHER_FILE, OUTPUT_OTHER_BASE64_FILE)

    total_saved = written_rus + written_other
    logging.info(f"📊 Всего сохранено ключей: {total_saved}")

if __name__ == "__main__":
    main()
