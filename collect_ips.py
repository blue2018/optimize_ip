import requests
from bs4 import BeautifulSoup
import re
import os
import ssl
import socket
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from ipaddress import ip_address

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

def try_socket_lookup(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

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
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
})

ip_seen = set()
ip_list = []

for url in urls:
    print(f"🔍 正在请求 {url}")
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[错误] 请求失败 {url}：{e}")
        # 试用 socket 域名解析作为备用方式
        domain = re.sub(r'^https?://', '', url).split('/')[0]
        fallback_ip = try_socket_lookup(domain)
        if fallback_ip and is_valid_ip(fallback_ip):
            print(f"🌐 域名解析获得 IP：{fallback_ip}")
            if fallback_ip not in ip_seen:
                ip_seen.add(fallback_ip)
                ip_list.append(fallback_ip)
        continue

    extracted = []
    content_type = response.headers.get('Content-Type', '')

    # JSON
    if 'application/json' in content_type or url.endswith('.json'):
        try:
            data = response.json()
            if isinstance(data, dict) and 'data' in data:
                for ip in data['data']:
                    if is_valid_ip(ip):
                        extracted.append(ip)
        except Exception as e:
            print(f"[错误] JSON 解析失败：{e}")

    # 纯文本
    elif url.endswith('.txt') or 'text/plain' in content_type:
        for line in response.text.splitlines():
            for ip in re.findall(ip_pattern, line):
                if is_valid_ip(ip):
                    extracted.append(ip)

    # HTML
    else:
        soup = BeautifulSoup(response.text, 'html.parser')
        elements = soup.find_all('tr') if 'vvhan.com' in url or '164746.xyz' in url else soup.find_all('li')
        for el in elements:
            text = ''.join(
                node for node in el.strings
            ).strip()
            for ip in re.findall(ip_pattern, text):
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

print(f"✅ 共提取 {len(ip_list)} 个唯一 IP（每源最多前 5 条，去重），保存于 ip.txt。")
with open('ip.txt', 'w') as f:
    for ip in ip_list:
        f.write(ip + '\n')
