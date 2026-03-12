#!/usr/bin/env python3
# GENERATOR.py – Двухуровневая проверка Vless/SS/Trojan/VMess/Hysteria2 серверов + флаги стран и города
# Ядро: sing‑box
# Логи: INFO – основные этапы, прогресс TLS (многопоточно), результаты проверок.
# После TCP‑уникализации TLS-проверка выполняется в 100 потоков с выводом каждого результата.
# Подписка сортируется: Россия, Европа, остальные; внутри по TTFB.
# Добавлена проверка TLS handshake и замер TTFB с порогом отсева.

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
import warnings
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning

sys.stdout.reconfigure(line_buffering=True)
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)],
    force=True
)

record_counter = 0
current_check = 0
total_checks = 0

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

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    logging.warning("⚠️ geoip2 не установлена. Флаги стран и города не будут добавлены.")

PROFILE_TITLE = "🇷🇺КРОТовыеТОННЕЛИ🇷🇺"
SUPPORT_URL = "🇷🇺КРОТовыеТОННЕЛИ🇷🇺"
PROFILE_WEB_PAGE_URL = "🇷🇺КРОТовыеТОННЕЛИ🇷🇺"
PROFILE_UPDATE_INTERVAL = "1"
SUBSCRIPTION_USERINFO = "upload=0; download=0; total=0; expire=0"

SOURCES_FILE = "sources.txt"
OUTPUT_FILE = "subscription.txt"
OUTPUT_BASE64_FILE = "subscription_base64.txt"
REQUEST_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
SING_BOX_PATH = "sing-box"

TCP_CHECK_TIMEOUT = 10
TCP_MAX_WORKERS = 400
TLS_CHECK_TIMEOUT = 5
TLS_MAX_WORKERS = 100          # параллельность TLS-проверки
MAX_TTFB_MS = 1000
SOCKS_PORT = 8080
REAL_CHECK_TIMEOUT = 15
REAL_CHECK_CONCURRENCY = 30
SING_BOX_STARTUP_DELAY = 1
TEST_URLS = ["http://connectivitycheck.gstatic.com/generate_204"]
MAX_LATENCY_MS = 300

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
    if len(flag) < 2:
        return 'ZZ'
    code = ''
    for ch in flag:
        if 127397 <= ord(ch) <= 127398 + 25:
            code += chr(ord(ch) - 127397)
    return code if len(code) == 2 else 'ZZ'

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
        path = None
        host_header = None
        if network == 'ws':
            path = params.get('path', ['/'])[0]
            host_header = params.get('host', [host])[0]
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
            'path': path,
            'host_header': host_header,
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

# ---------- TLS HANDSHAKE ----------
def check_tls_handshake(ip, port, sni):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=TLS_CHECK_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                ssock.do_handshake()
        return True
    except Exception:
        return False

def check_tls_item(link, ip, latency):
    """Выполняет TLS-проверку для одной ссылки, возвращает (ok, short_link)."""
    parsed = parse_link(link)
    if not parsed:
        return False, shorten_link(link)
    needs_tls = False
    if parsed['protocol'] == 'trojan':
        needs_tls = True
    elif parsed['protocol'] == 'vless':
        needs_tls = parsed.get('security') in ('tls', 'reality')
    elif parsed['protocol'] == 'vmess':
        needs_tls = parsed.get('tls', False)
    elif parsed['protocol'] == 'hysteria2':
        needs_tls = True
    if needs_tls:
        sni = parsed.get('sni', parsed['host'])
        ok = check_tls_handshake(ip, parsed['port'], sni)
        return ok, shorten_link(link)
    else:
        return True, shorten_link(link)

def measure_ttfb(proxies, url):
    try:
        start = time.time()
        resp = requests.get(
            url, proxies=proxies, timeout=REAL_CHECK_TIMEOUT,
            headers={'User-Agent': USER_AGENT}, stream=True
        )
        next(resp.iter_content(1))
        ttfb = int((time.time() - start) * 1000)
        resp.close()
        return ttfb
    except Exception:
        return None

# ---------- СОЗДАНИЕ КОНФИГА SING-BOX ----------
def create_singbox_config(config):
    inbound = {
        "type": "socks",
        "tag": "socks-in",
        "listen": "127.0.0.1",
        "listen_port": SOCKS_PORT
    }
    outbound_tag = "proxy"
    outbound = {}
    protocol = config['protocol']
    if protocol == 'ss':
        outbound = {
            "type": "shadowsocks",
            "tag": outbound_tag,
            "server": config['host'],
            "server_port": config['port'],
            "method": config['method'],
            "password": config['password']
        }
    elif protocol == 'trojan':
        outbound = {
            "type": "trojan",
            "tag": outbound_tag,
            "server": config['host'],
            "server_port": config['port'],
            "password": config['password']
        }
        outbound["tls"] = {
            "enabled": True,
            "server_name": config.get('sni', config['host']),
            "insecure": config.get('allow_insecure', False)
        }
        if config.get('network') == 'ws' and config.get('path'):
            outbound["transport"] = {
                "type": "ws",
                "path": config['path'],
                "headers": {
                    "Host": config.get('host_header', config['host'])
                }
            }
    elif protocol == 'vless':
        outbound = {
            "type": "vless",
            "tag": outbound_tag,
            "server": config['host'],
            "server_port": config['port'],
            "uuid": config['uuid']
        }
        if config.get('flow'):
            outbound["flow"] = config['flow']
        security = config.get('security', 'none')
        if security in ('tls', 'reality'):
            tls_settings = {
                "enabled": True,
                "server_name": config.get('sni', config['host']),
                "insecure": False
            }
            if security == 'reality':
                tls_settings["reality"] = {
                    "enabled": True,
                    "public_key": config.get('pbk', ''),
                    "short_id": config.get('sid', '')
                }
                if config.get('spx'):
                    tls_settings["reality"]["spider_x"] = config['spx']
            outbound["tls"] = tls_settings
        if config.get('type') == 'ws':
            outbound["transport"] = {
                "type": "ws",
                "path": config.get('path', '/'),
                "headers": {
                    "Host": config.get('host_header', config['host'])
                }
            }
    elif protocol == 'vmess':
        outbound = {
            "type": "vmess",
            "tag": outbound_tag,
            "server": config['host'],
            "server_port": config['port'],
            "uuid": config['uuid'],
            "security": config.get('security', 'auto')
        }
        if config.get('tls'):
            outbound["tls"] = {
                "enabled": True,
                "server_name": config.get('sni', config['host']),
                "insecure": config.get('allow_insecure', False)
            }
        if config.get('type') == 'ws':
            outbound["transport"] = {
                "type": "ws",
                "path": config.get('path', '/'),
                "headers": {
                    "Host": config.get('host_header', config['host'])
                }
            }
    elif protocol == 'hysteria2':
        outbound = {
            "type": "hysteria2",
            "tag": outbound_tag,
            "server": config['host'],
            "server_port": config['port'],
            "password": config['password'],
            "tls": {
                "enabled": True,
                "server_name": config.get('sni', config['host']),
                "insecure": config.get('allow_insecure', False)
            }
        }
        if config.get('obfs'):
            outbound["obfs"] = {"type": config['obfs']}
        if config.get('up'):
            try:
                outbound["up_mbps"] = int(config['up'])
            except:
                pass
        if config.get('down'):
            try:
                outbound["down_mbps"] = int(config['down'])
            except:
                pass
    else:
        logging.debug(f"Неподдерживаемый протокол: {protocol}")
        return None
    sb_config = {
        "log": {"level": "error"},
        "inbounds": [inbound],
        "outbounds": [outbound],
        "route": {
            "rules": [
                {"inbound": "socks-in", "outbound": outbound_tag}
            ]
        }
    }
    return sb_config

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

# ---------- РЕАЛЬНАЯ ПРОВЕРКА (с TTFB) ----------
def check_real(link):
    config_dict = parse_link(link)
    if not config_dict:
        return (link, False, None)
    sb_config = create_singbox_config(config_dict)
    if not sb_config:
        return (link, False, None)
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
        proxies = {
            'http': f'socks5h://127.0.0.1:{SOCKS_PORT}',
            'https': f'socks5h://127.0.0.1:{SOCKS_PORT}'
        }
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
        ttfb = None
        for test_url in TEST_URLS:
            ttfb = measure_ttfb(proxies, test_url)
            if ttfb is not None:
                break
        if ttfb is None or ttfb > MAX_TTFB_MS:
            return (link, False, ttfb)
        if needs_https:
            try:
                https_test = "https://www.google.com/generate_204"
                resp = requests.get(
                    https_test, proxies=proxies, timeout=REAL_CHECK_TIMEOUT,
                    headers={'User-Agent': USER_AGENT}, verify=False, stream=True
                )
                next(resp.iter_content(1))
                resp.close()
            except Exception:
                return (link, False, ttfb)
        return (link, True, ttfb)
    except Exception as e:
        logging.debug(f"Ошибка при проверке {link[:60]}: {e}")
        return (link, False, None)
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
    logging.info(f"🌐 Этап 1: TCP-проверка {total_checks} ссылок...")
    tcp_success = []
    with ThreadPoolExecutor(max_workers=TCP_MAX_WORKERS) as executor:
        future_to_link = {executor.submit(check_tcp, link): link for link in links}
        for future in as_completed(future_to_link):
            current_check += 1
            link, ok, ip, latency = future.result()
            if ok and ip and latency is not None and latency <= MAX_LATENCY_MS:
                tcp_success.append((link, ip, latency))
    logging.info(f"📊 TCP-проверка завершена. Прошли (latency <= {MAX_LATENCY_MS} мс): {len(tcp_success)}/{total_checks}")
    if not tcp_success:
        return []

    best_by_endpoint = {}
    for link, ip, latency in tcp_success:
        parsed = parse_link(link)
        if not parsed:
            continue
        port = parsed['port']
        key = (ip, port)
        if key not in best_by_endpoint or latency < best_by_endpoint[key][1]:
            best_by_endpoint[key] = (link, latency)
    unique_tcp = [(link, ip, latency) for (ip, port), (link, latency) in best_by_endpoint.items()]
    logging.info(f"🗂️ Уникальных (IP:порт) после TCP: {len(unique_tcp)} из {len(tcp_success)}")

    # Многопоточная TLS-проверка с выводом прогресса
    logging.info(f"🔒 Начинаю TLS-проверку для {len(unique_tcp)} серверов в {TLS_MAX_WORKERS} потоков...")
    tls_passed = []
    tls_total = len(unique_tcp)
    with ThreadPoolExecutor(max_workers=TLS_MAX_WORKERS) as executor:
        future_to_item = {}
        for link, ip, latency in unique_tcp:
            future = executor.submit(check_tls_item, link, ip, latency)
            future_to_item[future] = (link, ip, latency)

        completed = 0
        for future in as_completed(future_to_item):
            completed += 1
            link, ip, latency = future_to_item[future]
            ok, short = future.result()
            if ok:
                tls_passed.append((link, ip, latency))
                status = "✅"
            else:
                status = "❌"
            logging.info(f"{status} TLS handshake [{completed}/{tls_total}]: {short}")
            if completed % 100 == 0:
                logging.info(f"⏳ TLS-проверка: {completed}/{tls_total} выполнено")

    logging.info(f"🔒 TLS-проверка завершена. Прошли: {len(tls_passed)}/{tls_total}")
    unique_tcp = tls_passed
    if not unique_tcp:
        return []

    logging.info(f"🌍 Определение геоданных для {len(unique_tcp)} серверов...")
    geo_by_link = {}
    for link, ip, _ in unique_tcp:
        flag, city = get_geo_info(ip) if ip else ("", "")
        if flag:
            geo_by_link[link] = (flag, city)
    logging.info(f"🧾 Серверов с флагами: {len(geo_by_link)}")
    if not geo_by_link:
        return []

    logging.info(f"🧪 Этап 2: Реальная проверка (TTFB ≤ {MAX_TTFB_MS} мс) {len(geo_by_link)} ссылок...")
    working_links_with_geo = []
    stage_total = len(geo_by_link)
    stage_current = 0
    links_to_check = list(geo_by_link.keys())
    with ThreadPoolExecutor(max_workers=REAL_CHECK_CONCURRENCY) as executor:
        future_to_link = {executor.submit(check_real, link): link for link in links_to_check}
        for future in as_completed(future_to_link):
            stage_current += 1
            current_check += 1
            record_counter += 1
            link, is_working, ttfb = future.result()
            short = shorten_link(link)
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
                working_links_with_geo.append((link, flag, city, ttfb))
                emoji = "✅"
            else:
                emoji = "❌"
            log_msg = f"{proto} {emoji} [{stage_current}/{stage_total}]: {short} (ttfb={ttfb}ms)"
            logging.info(log_msg)
    logging.info(f"📊 Реальная проверка завершена. Рабочих с флагами: {len(working_links_with_geo)}/{stage_total}")
    return working_links_with_geo

# ---------- СОХРАНЕНИЕ РЕЗУЛЬТАТОВ ----------
def save_working_links(links_with_geo_ttfb):
    logging.info(f"💾 Сохраняю {len(links_with_geo_ttfb)} серверов с геоданными...")
    if not links_with_geo_ttfb:
        logging.warning("Нет серверов для сохранения.")
        return 0

    europe_codes = [
        'AT','BE','BG','CY','CZ','DE','DK','EE','ES','FI','FR','GR','HR','HU',
        'IE','IT','LT','LU','LV','MT','NL','PL','PT','RO','SE','SI','SK',
        'GB','CH','NO','IS','LI','AL','BA','RS','ME','MK','UA','BY','MD',
        'GE','AZ','AM','TR'
    ]

    def sort_key(item):
        link, flag, city, ttfb = item
        code = flag_to_country_code(flag)
        if code == 'RU':
            priority = 0
        elif code in europe_codes:
            priority = 1
        else:
            priority = 2
        return (priority, ttfb, code, city or '')

    links_with_geo_ttfb.sort(key=sort_key)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(f"#profile-title:{PROFILE_TITLE}\n")
        f.write(f"#subscription-userinfo:{SUBSCRIPTION_USERINFO}\n")
        f.write(f"#profile-update-interval:{PROFILE_UPDATE_INTERVAL}\n")
        f.write(f"#support-url:{SUPPORT_URL}\n")
        f.write(f"#profile-web-page-url:{PROFILE_WEB_PAGE_URL}\n")
        f.write(f"#announce: АКТИВНЫХ ТОННЕЛЕЙ 🚀 {len(links_with_geo_ttfb)} | ОБНОВЛЕНО 📅 {TODAY_STR}\n")
        for idx, (link, flag, city, ttfb) in enumerate(links_with_geo_ttfb, 1):
            link_clean = re.sub(r'#.*$', '', link)
            city_part = f" {city}" if city else ""
            tag = f"#🔑📱ТОННЕЛЬ {idx:04d} | {flag}{city_part} | TTFB={ttfb}ms"
            f.write(link_clean + tag + '\n')

    logging.info(f"✅ Сохранено {len(links_with_geo_ttfb)} серверов в {OUTPUT_FILE}")
    return len(links_with_geo_ttfb)

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

def main():
    global record_counter, current_check, total_checks
    logging.info("🟢 Запуск генератора подписок (ядро: sing-box; протоколы: Vless, SS, Trojan, VMess, Hysteria2)")
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
    working_links_with_geo_ttfb = filter_working_links(all_links)
    written = save_working_links(working_links_with_geo_ttfb)
    if written > 0:
        create_base64_subscription()
    else:
        logging.warning("Нет серверов с флагами – Base64 не создана.")
    logging.info(f"📊 Итог: {written} рабочих с флагами из {len(all_links)} проверенных")
    logging.info("🏁 Работа завершена")

if __name__ == "__main__":
    main()
