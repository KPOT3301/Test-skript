# Определяем флаги, города и коды стран для прошедших TCP
logging.info(f"🌍 Определение геоданных для {len(tcp_success)} серверов...")
geo_by_link = {}  # link -> (flag, city, country_code)
for link, ip, _ in tcp_success:
    flag, city, country_code = get_geo_info(ip) if ip else ("", "", "")
    if flag:
        geo_by_link[link] = (flag, city, country_code)

logging.info(f"🧾 Серверов с флагами: {len(geo_by_link)}")

# Фильтр: только Россия и Европа
european_countries = {
    'RU', 'AL', 'AD', 'AT', 'BY', 'BE', 'BA', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE',
    'FI', 'FR', 'DE', 'GR', 'HU', 'IS', 'IE', 'IT', 'LV', 'LI', 'LT', 'LU',
    'MT', 'MD', 'MC', 'ME', 'NL', 'MK', 'NO', 'PL', 'PT', 'RO', 'SM', 'RS',
    'SK', 'SI', 'ES', 'SE', 'CH', 'UA', 'GB', 'VA', 'TR'
}
filtered_geo = {
    link: data for link, data in geo_by_link.items()
    if data[2] in european_countries
}
logging.info(f"🌍 Российских и европейских: {len(filtered_geo)}")

if not filtered_geo:
    return []

# Этап 2: реальная проверка только для filtered_geo
logging.info(f"🧪 Этап 2: Реальная проверка {len(filtered_geo)} ссылок...")
working_links_with_geo = []  # (link, flag, city)
stage_total = len(filtered_geo)
stage_current = 0

links_to_check = list(filtered_geo.keys())

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

        flag, city, _ = filtered_geo[link]  # из отфильтрованного словаря

        if is_working:
            working_links_with_geo.append((link, flag, city))
            emoji = "✅"
        else:
            emoji = "❌"

        log_msg = f"{proto} {emoji} [{stage_current}/{stage_total}]: {short}"
        logging.info(log_msg)
