import requests
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
    'https://api.vvhan.com/tool/cf_ip',  # 换到 JSON 接口
    'https://ip.164746.xyz',                                  # HTML
    'https://github.com/hubbylei/bestcf/raw/refs/heads/main/bestcf.txt',  # 纯文本
    'https://addressesapi.090227.xyz/CloudFlareYes'           # JSON (其实是动态生成HTML表格)
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
        response = session.get(url, timeout=10)
        response.raise_for_status()
    except Exception as e:
        print(f"[错误] 无法请求 {url}：{e}")
        continue

    extracted = []
    ct = response.headers.get('Content-Type', '')

    # JSON 接口
    if 'application/json' in ct or url.endswith('/cf_ip'):
        try:
            data = response.json().get('data', {})
            for ipver in ['v4', 'v6']:
                if ipver in data:
                    for net in data[ipver]:
                        arr = data[ipver][net]
                        if isinstance(arr, list) and arr:
                            best = min(arr, key=lambda x: x.get('latency', float('inf')))
                            ip = best.get('ip')
                            if ip and is_valid_ip(ip):
                                extracted.append(ip)
        except Exception as e:
            print(f"[错误] JSON 解析失败 {url}：{e}")
            continue

    # 纯文本
    elif url.endswith('.txt') or 'text/plain' in ct:
        for line in response.text.splitlines():
            for ip in re.findall(ip_pattern, line):
                if is_valid_ip(ip):
                    extracted.append(ip)

    # HTML 页面
    else:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        elements = soup.find_all('tr') if 'cf.vvhan.com' in url or '164746.xyz' in url else soup.find_all('li')
        for el in elements:
            for td in el.find_all('td'):
                txt = ''.join(node for node in td.strings)
                for ip in re.findall(ip_pattern, txt):
                    if is_valid_ip(ip):
                        extracted.append(ip)

    # 去重并限制每源最多 5 条
    count = 0
    for ip in extracted:
        if ip not in ip_seen:
            ip_seen.add(ip)
            ip_list.append(ip)
            count += 1
            if count >= 5:
                break

# 写入
with open('ip.txt', 'w') as f:
    for ip in ip_list:
        f.write(ip + '\n')

print(f"✅ 共获取 {len(ip_list)} 个唯一 IP，保存至 ip.txt")
