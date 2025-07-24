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
import time

class TLSAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = ssl.create_default_context()
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

def is_valid_ip(ip):
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False

def extract_from_vvhan():
    # 启用无头浏览器
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    driver = webdriver.Chrome(ChromeDriverManager().install(), options=chrome_options)

    ip_list = []

    try:
        driver.get("https://cf.vvhan.com/")
        time.sleep(2)  # 等待 JS 渲染完成

        rows = driver.find_elements("tag name", "tr")
        for row in rows:
            tds = row.find_elements("tag name", "td")
            for td in tds:
                b_tags = td.find_elements("tag name", "b")
                ip_candidate = ''.join(b.text for b in b_tags)
                if is_valid_ip(ip_candidate):
                    ip_list.append(ip_candidate)
                if len(ip_list) >= 5:
                    break
            if len(ip_list) >= 5:
                break
    except Exception as e:
        print("[错误] Selenium 抓取 vvhan.com 失败：", e)
    finally:
        driver.quit()

    return ip_list

# 普通网页和API抓取
urls = [
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

# 先处理 vvhan.com（用 Selenium）
for ip in extract_from_vvhan():
    if ip not in ip_seen:
        ip_seen.add(ip)
        ip_list.append(ip)

# 处理其他 URL
for url in urls:
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
        except:
            continue
    elif url.endswith('.txt') or 'text/plain' in content_type:
        for line in response.text.splitlines():
            for ip in re.findall(ip_pattern, line):
                if is_valid_ip(ip):
                    extracted.append(ip)
    else:
        soup = BeautifulSoup(response.text, 'html.parser')
        rows = soup.find_all('tr')
        for row in rows:
            for td in row.find_all('td'):
                for ip in re.findall(ip_pattern, td.get_text()):
                    if is_valid_ip(ip):
                        extracted.append(ip)

    count = 0
    for ip in extracted:
        if ip not in ip_seen:
            ip_seen.add(ip)
            ip_list.append(ip)
            count += 1
            if count == 5:
                break

# 写入文件
with open('ip.txt', 'w') as f:
    for ip in ip_list:
        f.write(ip + '\n')

print(f"✅ 共提取 {len(ip_list)} 个唯一 IP 地址，已保存到 ip.txt")
