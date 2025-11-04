import requests
from bs4 import BeautifulSoup
import re
import os
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from ipaddress import ip_address

# 自定义 HTTPS 适配器
class TLSAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = ssl.create_default_context()
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

# 返回 ip 对象（用于判断是否有效 + 判断类型）
def is_valid_ip(ip):
    try:
        return ip_address(ip)
    except ValueError:
        return None

# 支持 IPv4 和 IPv6 的正则表达式
ip_pattern = r'(?:\d{1,3}\.){3}\d{1,3}|' \
             r'(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}'

# 数据来源
urls = [
    #'https://cf.vvhan.com/',   # HTML
    'https://ip.164746.xyz',   # HTML
    'https://raw.githubusercontent.com/hubbylei/bestcf/refs/heads/main/bestcf.txt',  # 纯文本
    'https://raw.githubusercontent.com/ymyuuu/IPDB/refs/heads/main/BestCF/bestcfv4.txt',
    'https://raw.githubusercontent.com/ZhiXuanWang/cf-speed-dns/refs/heads/main/ipTop10.html',
    'https://addressesapi.090227.xyz/CloudFlareYes'  # JSON (动态HTML)
]

# 删除旧文件
if os.path.exists('ip.txt'):
    os.remove('ip.txt')

# 请求会话
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

    # JSON 格式
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

    # 文本格式
    elif url.endswith('.txt') or 'text/plain' in content_type:
        lines = response.text.splitlines()
        for line in lines:
            ip_matches = re.findall(ip_pattern, line)
            for ip in ip_matches:
                if is_valid_ip(ip):
                    extracted.append(ip)

    # HTML 格式
    else:
        soup = BeautifulSoup(response.text, 'html.parser')
        elements = soup.find_all('tr') if url in [
            'https://cf.vvhan.com/',
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

    # 获取第4至第8个唯一IP（索引3-7）
    source_unique = []
    for ip in extracted:
        if ip not in source_unique:
            source_unique.append(ip)
    
    # 跳过前3个，获取第4-8个（共5个）
    selected = source_unique[3:8]
    
    for ip in selected:
        if ip not in ip_seen:
            ip_seen.add(ip)
            ip_list.append(ip)
    
    print(f"[来源] {url} - 提取了 {len(selected)} 个IP（第4-8个）")

# 写入文件，IPv6 加中括号
with open('ip.txt', 'w', encoding='utf-8') as file:
    for ip in ip_list:
        ip_obj = is_valid_ip(ip)
        if ip_obj:
            formatted_ip = f"[{ip}]" if ip_obj.version == 6 else ip
            file.write(formatted_ip + '\n')

print(f"✅ 共提取 {len(ip_list)} 个唯一 IP（IPv4 + IPv6），IPv6 已加中括号，已保存到 ip.txt。")
