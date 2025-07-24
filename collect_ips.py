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
    'https://cf.vvhan.com/',   # HTML 
    #'https://ip.164746.xyz',                                  # HTML
    #'https://github.com/hubbylei/bestcf/raw/refs/heads/main/bestcf.txt',  # 纯文本
    #'https://addressesapi.090227.xyz/CloudFlareYes'           # JSON (其实是动态生成HTML表格)
]

ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

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

    # JSON 格式
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
        # 注意这里 https://cf.090227.xyz 返回的是动态生成的表格结构，使用tr获取行
        elements = soup.find_all('tr') if url in [
            'https://cf.vvhan.com/',
            'https://ip.164746.xyz'
        ] else soup.find_all('li')

        for element in elements:
            tds = element.find_all('td')
            for td in tds:
                # 合并所有直接字符串节点，避免 <b> 拆分数字导致拼接错误
                parts = []
                for node in td.descendants:
                    if isinstance(node, str):
                        parts.append(node)
                combined = ''.join(parts).strip()
                # 只保留有效 IP
                for match in re.findall(ip_pattern, combined):
                    if is_valid_ip(match):
                        extracted.append(match)

    # 去重并仅保留前 5 条有效 IP
    count = 0
    for ip in extracted:
        if ip not in ip_seen:
            ip_seen.add(ip)
            ip_list.append(ip)
            count += 1
            if count == 5:
                break

# 写入文件（按原始顺序）
with open('ip.txt', 'w') as file:
    for ip in ip_list:
        file.write(ip + '\n')

print(f"✅ 共提取 {len(ip_list)} 个唯一 IP 地址（每源前 5 条，去重后），已保存到 ip.txt。")
