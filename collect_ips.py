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
    #'https://raw.githubusercontent.com/lu-lingyun/CloudflareST/refs/heads/main/TLS.txt',  # 纯文本
    #'https://addressesapi.090227.xyz/ip.164746.xyz'           # JSON
]

ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

if os.path.exists('ip.txt'):
    os.remove('ip.txt')

session = requests.Session()
session.mount('https://', TLSAdapter())

unique_ips = set()

for url in urls:
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[错误] 无法请求 {url}：{e}")
        continue

    content_type = response.headers.get('Content-Type', '')

    # 判断 JSON 格式
    if 'application/json' in content_type or url.endswith('.json'):
        try:
            data = response.json()
            if isinstance(data, dict) and 'data' in data:
                ip_list = data['data']
                for ip in ip_list:
                    if re.fullmatch(ip_pattern, ip):
                        unique_ips.add(ip)
        except Exception as e:
            print(f"[错误] JSON 解析失败：{e}")
            continue

    # 判断纯文本格式
    elif url.endswith('.txt') or 'text/plain' in content_type:
        lines = response.text.splitlines()
        for line in lines:
            ip_matches = re.findall(ip_pattern, line)
            unique_ips.update(ip_matches)

    # 其他情况默认当作 HTML
    else:
        soup = BeautifulSoup(response.text, 'html.parser')
        elements = soup.find_all('tr') if url in [
            #'https://monitor.gacjie.cn/page/cloudflare/ipv4.html',
            'https://ip.164746.xyz'
        ] else soup.find_all('li')
        for element in elements:
            text = element.get_text()
            ip_matches = re.findall(ip_pattern, text)
            unique_ips.update(ip_matches)

# 写入 IP 文件
with open('ip.txt', 'w') as file:
    for ip in sorted(unique_ips):
        file.write(ip + '\n')

print(f"✅ 共提取 {len(unique_ips)} 个唯一 IP 地址，已保存到 ip.txt。")
