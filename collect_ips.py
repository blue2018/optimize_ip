import requests
from bs4 import BeautifulSoup
import re
import os
import ssl
import time
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
        return ip_address(ip)
    except ValueError:
        return None

# ⚡ 用 HTTP 请求延迟代替 ping（在 GitHub 上可运行）
def http_ping(ip):
    ip_obj = is_valid_ip(ip)
    if not ip_obj:
        return None

    url = f"https://[{ip}]" if ip_obj.version == 6 else f"http://{ip}"
    try:
        start = time.time()
        # Cloudflare 节点多数支持 HTTP 请求
        requests.get(url, timeout=2)
        return (time.time() - start) * 1000  # 转换为毫秒
    except Exception:
        return None

ip_pattern = r'(?:\d{1,3}\.){3}\d{1,3}|' \
             r'(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}'

urls = [
    'https://ip.164746.xyz',
    'https://raw.githubusercontent.com/hubbylei/bestcf/refs/heads/main/bestcf.txt',
    'https://raw.githubusercontent.com/ymyuuu/IPDB/refs/heads/main/BestCF/bestcfv4.txt',
    'https://raw.githubusercontent.com/ZhiXuanWang/cf-speed-dns/refs/heads/main/ipTop10.html',
    'https://addressesapi.090227.xyz/CloudFlareYes'
]

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
                    ip_obj = is_valid_ip(ip)
                    if ip_obj:
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
        elements = soup.find_all('tr') if url in [
            'https://cf.vvhan.com/',
            'https://ip.164746.xyz'
        ] else soup.find_all('li')

        for element in elements:
            text = ''.join(t.get_text(strip=True) for t in element.find_all('td') or [element])
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

# ⚙️ 使用 HTTP 请求延迟替代 ping
ping_results = []
print("\n开始 HTTP 延迟测试（GitHub 环境）...\n")
for ip in ip_list:
    latency = http_ping(ip)
    if latency is not None:
        print(f"{ip:<40} → {latency:.1f} ms")
        if latency >= 100:
            ping_results.append((ip, latency))
    else:
        print(f"{ip:<40} → 无响应")

ping_results.sort(key=lambda x: x[1])

with open('ip.txt', 'w', encoding='utf-8') as f:
    for ip, ms in ping_results:
        ip_obj = is_valid_ip(ip)
        formatted_ip = f"[{ip}]" if ip_obj.version == 6 else ip
        f.write(f"{formatted_ip}  {ms:.1f}ms\n")

print(f"\n✅ 共提取 {len(ping_results)} 个 HTTP 延迟 ≥100ms 的 IP，已保存到 ip.txt。")
