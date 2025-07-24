import requests
from bs4 import BeautifulSoup
import re
import os
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from ipaddress import ip_address
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

# --- 用于 requests 的 TLS 适配器 ---
class TLSAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = ssl.create_default_context()
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

# --- IP 地址合法性检查 ---
def is_valid_ip(ip):
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False

# --- 使用 selenium 抓取 cf.vvhan.com 的 IP 地址 ---
def fetch_cf_vvhan_ips():
    options = Options()
    options.headless = True
    driver = webdriver.Chrome(ChromeDriverManager().install(), options=options)
    driver.get("https://cf.vvhan.com/")

    html = driver.page_source
    soup = BeautifulSoup(html, 'html.parser')
    ips = []

    for tr in soup.find_all('tr'):
        for td in tr.find_all('td'):
            text = td.get_text(strip=True)
            for match in re.findall(ip_pattern, text):
                if is_valid_ip(match):
                    ips.append(match)
    driver.quit()
    return ips[:5]  # 返回前5个唯一IP

# --- 主处理逻辑 ---
urls = [
    'https://cf.vvhan.com/',
    'https://ip.164746.xyz',
    'https://github.com/hubbylei/bestcf/raw/refs/heads/main/bestcf.txt',
    'https://addressesapi.090227.xyz/CloudFlareYes'
]

ip_pattern = r'\d{1,3}(?:\.\d{1,3}){3}'

if os.path.exists('ip.txt'):
    os.remove('ip.txt')

session = requests.Session()
session.mount('https://', TLSAdapter())

ip_seen = set()
ip_list = []

for url in urls:
    print(f"📡 正在处理：{url}")

    # 对 cf.vvhan.com 使用 selenium
    if url == 'https://cf.vvhan.com/':
        try:
            extracted = fetch_cf_vvhan_ips()
        except Exception as e:
            print(f"[错误] Selenium 获取 {url} 失败：{e}")
            continue
    else:
        try:
            response = session.get(url, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"[错误] 无法请求 {url}：{e}")
            continue

        content_type = response.headers.get('Content-Type', '')
        extracted = []

        if 'application/json' in content_type or url.endswith('.json'):
            try:
                data = response.json()
                if isinstance(data, dict) and 'data' in data:
                    for ip in data['data']:
                        if is_valid_ip(ip):
                            extracted.append(ip)
            except Exception as e:
                print(f"[错误] JSON 解析失败：{e}")
                continue

        elif url.endswith('.txt') or 'text/plain' in content_type:
            for line in response.text.splitlines():
                for ip in re.findall(ip_pattern, line):
                    if is_valid_ip(ip):
                        extracted.append(ip)

        else:
            soup = BeautifulSoup(response.text, 'html.parser')
            elements = soup.find_all('tr') if url == 'https://ip.164746.xyz' else soup.find_all('li')

            for element in elements:
                tds = element.find_all('td')
                for td in tds:
                    parts = [node for node in td.descendants if isinstance(node, str)]
                    combined = ''.join(parts).strip()
                    for match in re.findall(ip_pattern, combined):
                        if is_valid_ip(match):
                            extracted.append(match)

    # 每个源最多保留前 5 个唯一 IP
    count = 0
    for ip in extracted:
        if ip not in ip_seen:
            ip_seen.add(ip)
            ip_list.append(ip)
            count += 1
            if count == 5:
                break

# 写入文件
with open('ip.txt', 'w') as file:
    for ip in ip_list:
        file.write(ip + '\n')

print(f"✅ 共提取 {len(ip_list)} 个唯一 IP 地址（每源前 5 条，去重后），已保存到 ip.txt。")
