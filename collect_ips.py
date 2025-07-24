import requests
from bs4 import BeautifulSoup
import re
import os
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from ipaddress import ip_address

class TLSAdapter(HTTPAdapter):
    """兼容云端环境的 TLS 适配器"""
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

def extract_ips_from_json(data):
    ips = []
    if isinstance(data, dict):
        # 支持 { "data": [...] } 或直接 list
        candidates = data.get('data', data if isinstance(data, list) else [])
        for ip in candidates:
            if isinstance(ip, str) and is_valid_ip(ip):
                ips.append(ip)
    return ips

def extract_ips_from_text(text, pattern):
    return [ip for ip in re.findall(pattern, text) if is_valid_ip(ip)]

def extract_ips_from_html(html, tag_choice='tr'):
    soup = BeautifulSoup(html, 'html.parser')
    elements = soup.find_all(tag_choice)
    ips = []
    for el in elements:
        text = ''.join(node for node in el.strings).strip()
        ips.extend(extract_ips_from_text(text, ip_pattern))
    return ips

# 配置源 URL 列表
urls = [
    'https://cf.vvhan.com/',   # HTML Cloudflare 节点（tr）
    'https://ip.164746.xyz',   # HTML 格式
    'https://github.com/hubbylei/bestcf/raw/refs/heads/main/bestcf.txt',  # 纯文本
    'https://addressesapi.090227.xyz/CloudFlareYes'  # 动态 HTML 表格
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
        resp = session.get(url, timeout=15)
        resp.raise_for_status()
    except Exception as e:
        print(f"[错误] 请求失败 {url}：{e}")
        continue

    ctype = resp.headers.get('Content-Type', '').lower()
    collected = []

    if 'application/json' in ctype or url.endswith('.json'):
        try:
            collected = extract_ips_from_json(resp.json())
        except Exception as e:
            print(f"[错误] JSON 解析失败：{e}")
            continue

    elif url.endswith('.txt') or 'text/plain' in ctype:
        collected = extract_ips_from_text(resp.text, ip_pattern)

    else:
        # HTML 页面，选择 tr 元素提取
        collected = extract_ips_from_html(resp.text, tag_choice='tr')

        # 额外尝试 li 元素，兼容非表格结构
        if not collected:
            collected = extract_ips_from_html(resp.text, tag_choice='li')

    # 加入结果，最多前 5 条
    count = 0
    for ip in collected:
        if ip not in ip_seen:
            ip_seen.add(ip)
            ip_list.append(ip)
            count += 1
            if count >= 5:
                break

print(f"✅ 共收集 {len(ip_list)} 个唯一 IP，写入 ip.txt。")
with open('ip.txt', 'w') as fw:
    fw.write('\n'.join(ip_list))
