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

def get_ip_info(ip):
    """使用 韩小韩 Web API 获取单个 IP 的地理信息（国家/省/市）"""
    url = 'https://api.vvhan.com/api/ipInfo'
    params = {'ip': ip}
    resp = requests.get(url, params=params, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    info = data.get('info', {})
    return {
        'ip': ip,
        'country': info.get('country', ''),
        'prov': info.get('prov', ''),
        'city': info.get('city', '')
    }

# 原始 URL 列表
urls = [
    'https://cf.vvhan.com/',
    'https://ip.164746.xyz',
    'https://github.com/hubbylei/bestcf/raw/refs/heads/main/bestcf.txt',
    'https://addressesapi.090227.xyz/CloudFlareYes'
]

ip_pattern = r'\d{1,3}(?:\.\d{1,3}){3}'

# 删除旧文件
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
    except Exception as e:
        print(f"[错误] 请求 {url} 失败：{e}")
        continue

    ct = resp.headers.get('Content-Type', '')
    extracted = []

    if 'application/json' in ct or url.endswith('.json'):
        try:
            js = resp.json()
            for ip in js.get('data', []):
                if is_valid_ip(ip):
                    extracted.append(ip)
        except:
            pass

    elif url.endswith('.txt') or 'text/plain' in ct:
        for line in resp.text.splitlines():
            for ip in re.findall(ip_pattern, line):
                if is_valid_ip(ip):
                    extracted.append(ip)

    else:
        soup = BeautifulSoup(resp.text, 'html.parser')
        elements = soup.find_all('tr') if url in urls[:2] else soup.find_all('li')
        for e in elements:
            for td in e.find_all('td'):
                combined = ''.join(node for node in td.descendants if isinstance(node, str)).strip()
                for ip in re.findall(ip_pattern, combined):
                    if is_valid_ip(ip):
                        extracted.append(ip)

    # 每源前 5 条去重
    cnt = 0
    for ip in extracted:
        if ip not in ip_seen:
            ip_seen.add(ip)
            ip_list.append(ip)
            cnt += 1
            if cnt >= 5:
                break

# 写入 ip.txt
with open('ip.txt', 'w') as f:
    for ip in ip_list:
        f.write(ip + '\n')

print(f"✅ 共提取 {len(ip_list)} 个唯一 IP，已写入 ip.txt")

# 调用 API 获取地理信息
print("\n📌 IP 地理信息如下：")
for ip in ip_list:
    try:
        info = get_ip_info(ip)
        print(f"- {ip} → 国家：{info['country']}，省：{info['prov']}，市：{info['city']}")
    except Exception as e:
        print(f"- {ip} → 获取信息失败：{e}")
