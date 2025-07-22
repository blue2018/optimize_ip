import requests
from bs4 import BeautifulSoup
import re
import os
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

class TLSAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = ssl.create_default_context()
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

urls = [
    #'https://monitor.gacjie.cn/page/cloudflare/ipv4.html',   # HTML 
    'https://ip.164746.xyz',                                  # HTML
    'https://raw.githubusercontent.com/lu-lingyun/CloudflareST/refs/heads/main/TLS.txt',  # 纯文本
    'https://cf.090227.xyz'           # JSON 
]

ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

if os.path.exists('ip.txt'):
    os.remove('ip.txt')

session = requests.Session()
session.mount('https://', TLSAdapter())

seen_ips = set()
final_ips = []

for url in urls:
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[错误] 无法请求 {url}：{e}")
        continue

    content_type = response.headers.get('Content-Type', '')
    page_ips = []

    if 'application/json' in content_type or url.endswith('.json'):
        try:
            data = response.json()
            if isinstance(data, dict) and 'data' in data:
                for ip in data['data']:
                    if re.fullmatch(ip_pattern, ip) and ip not in seen_ips:
                        page_ips.append(ip)
                        seen_ips.add(ip)
                    if len(page_ips) >= 5:
                        break
        except Exception as e:
            print(f"[错误] JSON 解析失败：{e}")
            continue

    elif url.endswith('.txt') or 'text/plain' in content_type:
        for line in response.text.splitlines():
            if len(page_ips) >= 5:
                break
            for ip in re.findall(ip_pattern, line):
                if ip not in seen_ips:
                    page_ips.append(ip)
                    seen_ips.add(ip)
                if len(page_ips) >= 5:
                    break

    else:
        soup = BeautifulSoup(response.text, 'html.parser')
        elements = soup.find_all('tr') if url in [
            'https://ip.164746.xyz',
            'https://cf.090227.xyz'            
        ] else soup.find_all('li')
        for element in elements:
            if len(page_ips) >= 5:
                break
            for ip in re.findall(ip_pattern, element.get_text()):
                if ip not in seen_ips:
                    page_ips.append(ip)
                    seen_ips.add(ip)
                if len(page_ips) >= 5:
                    break

    final_ips.extend(page_ips)

# 写入文件
with open('ip.txt', 'w') as f:
    for ip in final_ips:
        f.write(ip + '\n')

print(f"✅ 共提取 {len(final_ips)} 个唯一 IP（每页最多5个），已按顺序保存至 ip.txt。")
