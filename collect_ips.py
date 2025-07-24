import requests
from bs4 import BeautifulSoup
import re
import os
import ssl
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

urls = [
    'https://cf.vvhan.com/',   # HTML with table
    'https://ip.164746.xyz',   # HTML
    'https://github.com/hubbylei/bestcf/raw/refs/heads/main/bestcf.txt',  # 纯文本
    'https://addressesapi.090227.xyz/CloudFlareYes'           # JSON dynamic HTML
]

ip_pattern = r'\d{1,3}(?:\.\d{1,3}){3}'

if os.path.exists('ip.txt'):
    os.remove('ip.txt')

session = requests.Session()
session.mount('https://', TLSAdapter())

ip_seen = set()
ip_list = []

for url in urls:
    try:
        resp = session.get(url, timeout=10)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[错误] 请求失败 {url}：{e}")
        continue

    content_type = resp.headers.get('Content-Type', '')
    extracted = []

    # JSON 返回类型
    if 'application/json' in content_type or url.endswith('.json'):
        try:
            data = resp.json()
            if isinstance(data, dict):
                if 'data' in data and isinstance(data['data'], list):
                    candidates = data['data']
                else:
                    # 如果直接是 IP 列表
                    candidates = [v for v in data.values() if isinstance(v, (list, str))]
                    if isinstance(candidates, list) and len(candidates) == 0:
                        candidates = []
                for item in candidates:
                    if isinstance(item, str) and is_valid_ip(item):
                        extracted.append(item)
            elif isinstance(data, list):
                for ip in data:
                    if isinstance(ip, str) and is_valid_ip(ip):
                        extracted.append(ip)
        except Exception as e:
            print(f"[错误] JSON 解析失败 {url}：{e}")
            continue

    # 纯文本格式
    elif url.endswith('.txt') or 'text/plain' in content_type:
        for line in resp.text.splitlines():
            for ip in re.findall(ip_pattern, line):
                if is_valid_ip(ip):
                    extracted.append(ip)

    # HTML 格式，统一用 tr + td 提取
    else:
        soup = BeautifulSoup(resp.text, 'html.parser')
        rows = soup.find_all('tr')
        # 有些页面可能用 <li> 包 IP 地址
        if not rows:
            rows = soup.find_all('li')
        for row in rows:
            text = ''.join(node for node in row.stripped_strings)
            for ip in re.findall(ip_pattern, text):
                if is_valid_ip(ip):
                    extracted.append(ip)

    # 去重、限制每源最多5条
    count = 0
    for ip in extracted:
        if ip not in ip_seen:
            ip_seen.add(ip)
            ip_list.append(ip)
            count += 1
            if count >= 5:
                break

# 写入文件
with open('ip.txt', 'w') as f:
    for ip in ip_list:
        f.write(ip + '\n')

print(f"✅ 提取到 {len(ip_list)} 个唯一 IP，已写入 ip.txt")
