import requests
from bs4 import BeautifulSoup
import re
import os
import ssl
import platform
import subprocess
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

# Ping 测试函数
def ping_ip(ip, count=4):
    """
    对 IP 进行 ping 测试，返回平均延迟（ms）
    如果 ping 失败，返回 None
    """
    # 移除 IPv6 的中括号
    ip_clean = ip.strip('[]')
    
    # 判断操作系统
    system = platform.system().lower()
    
    # 构建 ping 命令
    if system == 'windows':
        cmd = ['ping', '-n', str(count), '-w', '3000', ip_clean]
    else:  # Linux/Mac
        cmd = ['ping', '-c', str(count), '-W', '3', ip_clean]
    
    try:
        # 执行 ping 命令
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            text=True
        )
        
        if result.returncode != 0:
            return None
        
        output = result.stdout
        
        # 解析平均延迟
        if system == 'windows':
            # Windows: 平均 = XXXms
            match = re.search(r'平均\s*=\s*(\d+)ms', output)
            if not match:
                match = re.search(r'Average\s*=\s*(\d+)ms', output)
        else:
            # Linux/Mac: rtt min/avg/max/mdev = XX/XX/XX/XX ms
            match = re.search(r'min/avg/max/[^=]+=\s*[\d.]+/([\d.]+)/', output)
        
        if match:
            return float(match.group(1))
        return None
        
    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
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

print("=" * 60)
print("步骤 1：从各来源提取 IP 地址")
print("=" * 60)

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

    # 每来源最多提取 5 个唯一 IP
    count = 0
    for ip in extracted:
        if ip not in ip_seen:
            ip_seen.add(ip)
            ip_list.append(ip)
            count += 1
            if count == 5:
                break
    
    print(f"[来源] {url[:50]}... 提取了 {count} 个IP")

print(f"\n初步提取到 {len(ip_list)} 个唯一 IP")

# Ping 测试
print("\n" + "=" * 60)
print("步骤 2：Ping 测试所有 IP（这可能需要一些时间...）")
print("=" * 60)

ip_with_ping = []

for i, ip in enumerate(ip_list, 1):
    print(f"[{i}/{len(ip_list)}] 正在测试 {ip}...", end=' ', flush=True)
    
    ping_time = ping_ip(ip)
    
    if ping_time is not None:
        print(f"✓ {ping_time:.1f} ms")
        ip_with_ping.append((ip, ping_time))
    else:
        print("✗ 无响应")

# 过滤并排序（只保留 ping >= 100ms 的IP）
filtered_ips = [(ip, ping) for ip, ping in ip_with_ping if ping >= 100]
filtered_ips.sort(key=lambda x: x[1])  # 按 ping 值升序排序

print("\n" + "=" * 60)
print("步骤 3：保存结果")
print("=" * 60)

# 写入文件，IPv6 加中括号
with open('ip.txt', 'w', encoding='utf-8') as file:
    for ip, ping_time in filtered_ips:
        ip_obj = is_valid_ip(ip)
        if ip_obj:
            formatted_ip = f"[{ip}]" if ip_obj.version == 6 else ip
            file.write(f"{formatted_ip}\t# {ping_time:.1f} ms\n")

print(f"\n✅ 共保留 {len(filtered_ips)} 个 IP (ping ≥ 100ms)")
if filtered_ips:
    print(f"📊 Ping 范围: {filtered_ips[0][1]:.1f} ms ~ {filtered_ips[-1][1]:.1f} ms")
    print(f"💾 已保存到 ip.txt")
    
    print("\n延迟最低的前 5 个 IP:")
    for ip, ping_time in filtered_ips[:5]:
        print(f"  {ip}\t{ping_time:.1f} ms")
else:
    print("⚠️ 没有找到 ping 值 ≥ 100ms 的 IP")
