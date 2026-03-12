#!/usr/bin/env python3
# GENERATOR.py – Двухуровневая проверка Vless/SS/Trojan/VMess/Hysteria2 серверов + флаги стран и города
# Версия с многопоточной TLS-проверкой и ядром Sing-box. Оптимизировано для GitHub Actions.

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
SING_BOX_CORE_PATH = "sing-box"  # заменено с xray на sing-box

# TCP-проверка
TCP_CHECK_TIMEOUT = 10
TCP_MAX_WORKERS = 400

# Реальная проверка (через Sing-box)
SOCKS_PORT = 1080  # стандартный порт для sing-box socks
REAL_CHECK_TIMEOUT = 15
REAL_CHECK_CONCURRENCY = 30
SING_BOX_STARTUP_DELAY = 1

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
    # Добавлены vmess и hysteria2/hy2
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

# ---------- ПАРСЕРЫ (оставлены без изменений, см. предыдущие версии) ----------
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

# ---------- TLS-ПРОВЕРКА (новая функция) ----------
def tls_check(link, parsed):
    """Пытается установить TLS-соединение с хостом:порт, используя SNI из parsed"""
    host = parsed['host']
    port = parsed['port']
    sni = parsed.get('sni', host)
    try:
        ip = resolve_host(host)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=TCP_CHECK_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                # просто устанавливаем соединение, дополнительных проверок не нужно
                pass
        return True
    except Exception:
        return False

# ---------- СОЗДАНИЕ КОНФИГА SING-BOX ----------
def create_singbox_config(config):
    """Формирует конфигурацию для sing-box на основе распарсенных данных"""
    protocol = config['protocol']

    # Базовый конфиг с inbound (SOCKS5 на локальном порту)
    outbound = {}

    if protocol == 'vless':
        outbound = {
            "type": "vless",
            "server": config['host'],
            "server_port": config['port'],
            "uuid": config['uuid'],
            "flow": config.get('flow', ''),
            "packet_encoding": "xudp"
        }
        if config.get('security') == 'tls':
            outbound["tls"] = {
                "enabled": True,
                "server_name": config.get('sni', config['host']),
                "utls": {
                    "enabled": True,
                    "fingerprint": config.get('fp', 'chrome')
                }
            }
        elif config.get('security') == 'reality':
            outbound["tls"] = {
                "enabled": True,
                "server_name": config.get('sni', config['host']),
                "reality": {
                    "enabled": True,
                    "public_key": config.get('pbk', ''),
                    "short_id": config.get('sid', '')
                },
                "utls": {
                    "enabled": True,
                    "fingerprint": config.get('fp', 'chrome')
                }
            }
        # Транспорт
        if config.get('type') == 'ws':
            outbound["transport"] = {
                "type": "ws",
                "path": config.get('path', '/'),
                "headers": {
                    "Host": config.get('host_header', config['host'])
                }
            }
        # Другие транспорты можно добавить при необходимости

    elif protocol == 'vmess':
        outbound = {
            "type": "vmess",
            "server": config['host'],
            "server_port": config['port'],
            "uuid": config['uuid'],
            "security": config.get('security', 'auto'),
            "packet_encoding": "packetaddr"
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

    elif protocol == 'ss':
        outbound = {
            "type": "shadowsocks",
            "server": config['host'],
            "server_port": config['port'],
            "method": config['method'],
            "password": config['password']
        }

    elif protocol == 'trojan':
        outbound = {
            "type": "trojan",
            "server": config['host'],
            "server_port": config['port'],
            "password": config['password']
        }
        if config.get('security') == 'tls':
            outbound["tls"] = {
                "enabled": True,
                "server_name": config.get('sni', config['host']),
                "insecure": config.get('allow_insecure', False)
            }
        if config.get('network') == 'ws':
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
            "server": config['host'],
            "server_port": config['port'],
            "password": config['password'],
            "tls": {
                "enabled": True,
                "server_name": config.get('sni', config['host']),
                "insecure": config.get('allow_insecure', False)
            }
        }
        if config.get('up') or config.get('down'):
            outbound["bandwidth"] = {}
            if config.get('up'):
                outbound["bandwidth"]["up"] = config['up']
            if config.get('down'):
                outbound["bandwidth"]["down"] = config['down']
        if config.get('obfs'):
            outbound["obfs"] = {
                "type": config['obfs'],
                "password": config.get('obfs_password', '')
            }

    else:
        return None

    # Собираем полный конфиг
    sing_config = {
        "log": {
            "level": "error",
            "output": ""  # в stderr
        },
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": SOCKS_PORT,
                "users": []
            }
        ],
        "outbounds": [outbound]
    }
    return sing_config

# ---------- TCP ПРОВЕРКА (возвращает IP и задержку при успехе) ----------
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

# ---------- РЕАЛЬНАЯ ПРОВЕРКА (через Sing-box, однократная) ----------
def check_real(link):
    config_dict = parse_link(link)
    if not config_dict:
        return (link, False)
    sing_config = create_singbox_config(config_dict)
    if not sing_config:
        return (link, False)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config_path = f.name
        json.dump(sing_config, f, indent=2)

    process = None
    try:
        process = subprocess.Popen(
            [SING_BOX_CORE_PATH, 'run', '-c', config_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        time.sleep(SING_BOX_STARTUP_DELAY)
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

        # Однократная HTTP-проверка
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

# ---------- ДВУХУРОВНЕВАЯ ФИЛЬТРАЦИЯ С ОТСЕВОМ ПО TCP, TLS И РЕАЛЬНОЙ ПРОВЕРКОЙ ----------
def filter_working_links(links):
    global record_counter, current_check, total_checks
    total_checks = len(links)
    logging.info(f"🚀 Начинаю двухуровневую проверку {total_checks} ссылок")

    # Этап 1: TCP-проверка + замер задержки
    logging.info(f"🌐 TCP-проверка {total_checks} ссылок...")
    tcp_success = []  # (link, ip, latency_ms)
    with ThreadPoolExecutor(max_workers=TCP_MAX_WORKERS) as executor:
        future_to_link = {executor.submit(check_tcp, link): link for link in links}
        for future in as_completed(future_to_link):
            current_check += 1
            link, ok, ip, latency = future.result()
            if ok and ip and latency is not None and latency <= MAX_LATENCY_MS:
                tcp_success.append((link, ip, latency))
    logging.info(f"📊 TCP-проверка завершена. Прошли (latency ≤ {MAX_LATENCY_MS} мс): {len(tcp_success)}/{total_checks}")

    if not tcp_success:
        return []

    # Определяем геоданные
    logging.info(f"🌍 Определение геоданных для {len(tcp_success)} серверов...")
    geo_by_link = {}  # link -> (flag, city)
    for link, ip, _ in tcp_success:
        flag, city = get_geo_info(ip) if ip else ("", "")
        if flag:
            geo_by_link[link] = (flag, city)
    logging.info(f"🧾 Серверов с флагами: {len(geo_by_link)}")

    if not geo_by_link:
        return []

    # Этап 2: TLS-проверка (параллельно)
    logging.info(f"🔒 TLS-проверка {len(geo_by_link)} серверов...")
    tls_passed = []
    tls_failed = 0

    def check_tls_wrapper(link):
        parsed = parse_link(link)
        if not parsed:
            return False
        # Проверяем, нужен ли TLS
        if parsed['protocol'] in ('vless', 'vmess', 'trojan', 'hysteria2'):
            # Для vless с security=reality пропускаем TLS-проверку
            if parsed['protocol'] == 'vless' and parsed.get('security') == 'reality':
                return True  # Reality не требует TLS-рукопожатия
            # Для остальных выполняем проверку
            return tls_check(link, parsed)
        # Протоколы без TLS (ss) считаем прошедшими
        return True

    with ThreadPoolExecutor(max_workers=TCP_MAX_WORKERS) as executor:
        future_to_link = {executor.submit(check_tls_wrapper, link): link for link in geo_by_link.keys()}
        for future in as_completed(future_to_link):
            link = future_to_link[future]
            try:
                ok = future.result()
            except Exception:
                ok = False
            if ok:
                tls_passed.append(link)
            else:
                tls_failed += 1

    logging.info(f"🔐 TLS-проверка завершена. Прошли: {len(tls_passed)}, не прошли: {tls_failed}")

    if not tls_passed:
        return []

    # Этап 3: реальная проверка через Sing-box
    logging.info(f"🧪 Реальная проверка {len(tls_passed)} ссылок...")
    working_links_with_geo = []
    stage_total = len(tls_passed)
    stage_current = 0

    with ThreadPoolExecutor(max_workers=REAL_CHECK_CONCURRENCY) as executor:
        future_to_link = {executor.submit(check_real, link): link for link in tls_passed}
        for future in as_completed(future_to_link):
            stage_current += 1
            current_check += 1
            record_counter += 1
            link, is_working = future.result()
            flag, city = geo_by_link[link]

            if is_working:
                working_links_with_geo.append((link, flag, city))
                emoji = "✅"
            else:
                emoji = "❌"

            # Краткий лог (только протокол и результат)
            proto = link.split('://')[0]
            short = shorten_link(link)
            logging.info(f"{proto} {emoji} [{stage_current}/{stage_total}]: {short}")

    logging.info(f"📊 Реальная проверка завершена. Рабочих с флагами: {len(working_links_with_geo)}/{stage_total}")
    return working_links_with_geo

# ---------- СОХРАНЕНИЕ РЕЗУЛЬТАТОВ (С ФЛАГАМИ И ГОРОДАМИ) ----------
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

def check_singbox_available():
    logging.info("🔍 Проверка Sing-box...")
    try:
        result = subprocess.run([SING_BOX_CORE_PATH, 'version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            logging.info(f"✅ Sing-box: {result.stdout.splitlines()[0]}")
            return True
        else:
            logging.warning("⚠️ Sing-box не отвечает")
            return False
    except FileNotFoundError:
        logging.error(f"❌ Sing-box не найден по пути '{SING_BOX_CORE_PATH}'")
        return False
    except Exception as e:
        logging.error(f"❌ Ошибка проверки Sing-box: {e}")
        return False

# ---------- ГЛАВНАЯ ФУНКЦИЯ ----------
def main():
    global record_counter, current_check, total_checks
    logging.info("🟢 Запуск генератора подписок (протоколы: Vless, SS, Trojan, VMess, Hysteria2; ядро: Sing-box; TLS-проверка включена)")
    if not check_singbox_available():
        logging.error("Sing-box обязателен. Завершение.")
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
