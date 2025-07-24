from requests_html import HTMLSession
from bs4 import BeautifulSoup
import re
import os
from ipaddress import ip_address

def is_valid_ip(ip):
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False

urls = [
    'https://cf.vvhan.com/',   # 需要JS渲染
    'https://ip.164746.xyz',                                  # HTML
    'https://github.com/hubbylei/bestcf/raw/refs/heads/main/bestcf.txt',  # 纯文本
    'https://addressesapi.090227.xyz/CloudFlareYes'           # JSON (其实是动态生成HTML表格)
]

ip_pattern = r'\b\d{1,3}(?:\.\d{1,3}){3}\b'

if os.path.exists('ip.txt'):
    os.remove('ip.txt')

session = HTMLSession()

ip_seen = set()
ip_list = []

for url in urls:
    try:
        response = session.get(url, timeout=15)
        # 针对 https://cf.vvhan.com/ 需要渲染JS
        if url == 'https://cf.vvhan.com/':
            response.html.render(timeout=20, sleep=2)  # 渲染JS，睡2秒保证内容加载
    except Exception as e:
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

    # 纯文本格式
    elif url.endswith('.txt') or 'text/plain' in content_type:
        lines = response.text.splitlines()
        for line in lines:
            ip_matches = re.findall(ip_pattern, line)
            for ip in ip_matches:
                if is_valid_ip(ip):
                    extracted.append(ip)

    # HTML 格式
    else:
        # 用 requests-html 的 html 内容，仍然用BeautifulSoup解析会更稳定
        soup = BeautifulSoup(response.html.html, 'html.parser')

        # 针对 https://cf.vvhan.com/ 和 https://ip.164746.xyz 主要是 tr 行，其他网站用 li
        if url in ['https://cf.vvhan.com/', 'https://ip.164746.xyz']:
            elements = soup.find_all('tr')
        else:
            elements = soup.find_all('li')

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

    # 去重并仅保留前 5 条有效 IP
    count = 0
    for ip in extracted:
        if ip not in ip_seen:
            ip_seen.add(ip)
            ip_list.append(ip)
            count += 1
            if count == 5:
                break

with open('ip.txt', 'w') as file:
    for ip in ip_list:
        file.write(ip + '\n')

print(f"✅ 共提取 {len(ip_list)} 个唯一 IP 地址（每源前 5 条，去重后），已保存到 ip.txt。")
