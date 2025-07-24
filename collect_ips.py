import requests
from bs4 import BeautifulSoup
import re
import os
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from ipaddress import ip_address

# 新增requests_html，用于执行JS渲染
from requests_html import HTMLSession

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

urls = [
    'https://cf.vvhan.com/',   # 需要JS渲染处理
    'https://ip.164746.xyz',   # HTML
    'https://github.com/hubbylei/bestcf/raw/refs/heads/main/bestcf.txt',  # 纯文本
    'https://addressesapi.090227.xyz/CloudFlareYes'           # JSON
]

ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

if os.path.exists('ip.txt'):
    os.remove('ip.txt')

session = requests.Session()
session.mount('https://', TLSAdapter())

ip_seen = set()
ip_list = []

for url in urls:
    extracted = []

    try:
        if url == 'https://cf.vvhan.com/':
            # 用requests_html来获取动态渲染后的内容
            html_session = HTMLSession()
            r = html_session.get(url, timeout=10)
            r.html.render(timeout=20)
            soup = BeautifulSoup(r.html.html, 'html.parser')
            elements = soup.find_all('tr')

            for element in elements:
                tds = element.find_all('td')
                for td in tds:
                    parts = []
                    for node in td.descendants:
                        if isinstance(node, str):
                            parts.append(node)
                    combined = ''.join(parts).strip()
                    for match in re.findall(ip_pattern, combined):
                        if is_valid_ip(match):
                            extracted.append(match)

        else:
            response = session.get(url, timeout=10)
            response.raise_for_status()
            content_type = response.headers.get('Content-Type', '')

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
                lines = response.text.splitlines()
                for line in lines:
                    ip_matches = re.findall(ip_pattern, line)
                    for ip in ip_matches:
                        if is_valid_ip(ip):
                            extracted.append(ip)

            else:
                soup = BeautifulSoup(response.text, 'html.parser')
                elements = soup.find_all('tr') if url in [
                    'https://ip.164746.xyz'
                ] else soup.find_all('li')

                for element in elements:
                    tds = element.find_all('td')
                    for td in tds:
                        parts = []
                        for node in td.descendants:
                            if isinstance(node, str):
                                parts.append(node)
                        combined = ''.join(parts).strip()
                        for match in re.findall(ip_pattern, combined):
                            if is_valid_ip(match):
                                extracted.append(match)

    except requests.exceptions.RequestException as e:
        print(f"[错误] 无法请求 {url}：{e}")
        continue

    count = 0
    for ip in extracted:
        if ip not in ip_seen:
            ip_seen.add(ip)
            ip_list.append(ip)
            count += 1
            if count == 5:
                break

with open('ip.txt', 'w') as file:
    for ip in ip_list:
        file.write(ip + '\n')

print(f"✅ 共提取 {len(ip_list)} 个唯一 IP 地址（每源前 5 条，去重后），已保存到 ip.txt。")
