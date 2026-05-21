#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XSS漏洞扫描器
自动检测Web应用中GET参数是否存在跨站脚本攻击漏洞
"""

import requests
import argparse
import sys
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import payloads

# 禁用SSL警告
requests.packages.urllib3.disable_warnings()

# ========== 配置 ==========
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

TIMEOUT = 10  # 请求超时时间


def extract_params(url):
    """
    从URL中提取GET参数
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return {k: v[0] for k, v in params.items()}


def inject_param(url, param_name, payload):
    """
    将载荷注入到指定参数中
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param_name] = [payload]
    
    new_query = urlencode(params, doseq=True)
    new_parsed = parsed._replace(query=new_query)
    return urlunparse(new_parsed)


def check_reflection(response_text, payload):
    """
    检查载荷是否在响应中原样反射
    """
    if not payload or not response_text:
        return False
    
    # 1. 完全反射
    if payload in response_text:
        return True
    
    # 2. HTML实体编码后反射
    html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
    if html_encoded in response_text:
        return True
    
    # 3. URL编码后反射
    from urllib.parse import quote
    url_encoded = quote(payload)
    if url_encoded in response_text:
        return True
    
    return False


def check_xss_vulnerability(url, threads=10, use_advanced=False):
    """
    主检测函数
    """
    params = extract_params(url)
    
    if not params:
        print("[!] URL中没有GET参数，无法进行XSS测试")
        return None
    
    print(f"[*] 检测到 {len(params)} 个参数: {list(params.keys())}")
    
    # 加载载荷
    basic_payloads = payloads.load_payloads("payloads/basic.txt")
    if not basic_payloads:
        basic_payloads = payloads.get_builtin_payloads()
    
    advanced_payloads = []
    if use_advanced:
        advanced_payloads = payloads.load_payloads("payloads/advanced.txt")
    
    all_payloads = basic_payloads + advanced_payloads
    
    print(f"[*] 已加载 {len(all_payloads)} 个测试载荷")
    if use_advanced:
        print(f"    基础载荷: {len(basic_payloads)} 个")
        print(f"    高级绕过载荷: {len(advanced_payloads)} 个")
    
    total_tests = len(params) * len(all_payloads)
    print(f"[*] 总测试次数: {total_tests}")
    print(f"[*] 开始XSS漏洞扫描...\n")
    
    results = []
    
    with tqdm(total=total_tests, desc="扫描进度", unit="test") as pbar:
        for param_name in params:
            for payload in all_payloads:
                test_url = inject_param(url, param_name, payload)
                
                try:
                    response = requests.get(
                        test_url,
                        headers=DEFAULT_HEADERS,
                        timeout=TIMEOUT,
                        verify=False,
                        allow_redirects=True
                    )
                    
                    # 检查载荷是否反射
                    if check_reflection(response.text, payload):
                        result = {
                            'url': test_url,
                            'param': param_name,
                            'payload': payload,
                            'status_code': response.status_code,
                            'response_length': len(response.text),
                        }
                        results.append(result)
                        
                        tqdm.write(f"\n[+] 发现XSS漏洞!")
                        tqdm.write(f"    URL: {test_url}")
                        tqdm.write(f"    参数: {param_name}")
                        tqdm.write(f"    载荷: {payload}")
                        tqdm.write(f"    状态码: {response.status_code}")
                        
                except requests.exceptions.RequestException:
                    pass
                
                pbar.update(1)
    
    return results


def main():
    """
    命令行入口
    """
    parser = argparse.ArgumentParser(
        description="XSS漏洞扫描器 - 检测GET参数中的跨站脚本攻击漏洞",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python scanner.py -u "http://test.com/search.php?q=test"
  python scanner.py -u "http://test.com/page.php?id=1&name=admin"
  python scanner.py -u "http://test.com/search.php?q=test" --advanced
  python scanner.py -u "http://test.com/search.php?q=test" -t 20
  python scanner.py -u "http://test.com/search.php?q=test" -o result.txt
        """
    )
    
    parser.add_argument("-u", "--url", required=True,
                        help="目标URL（包含参数），例如 http://test.com/search.php?q=test")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="并发线程数（默认: 10）")
    parser.add_argument("-o", "--output",
                        help="结果输出文件路径")
    parser.add_argument("--advanced", action="store_true",
                        help="使用高级绕过载荷（包含大小写混淆、编码绕过等）")
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("XSS漏洞扫描器")
    print("=" * 50)
    print(f"[*] 目标URL: {args.url}")
    print(f"[*] 线程数: {args.threads}")
    print(f"[*] 高级模式: {'开启' if args.advanced else '关闭'}")
    print()
    
    # 执行扫描
    results = check_xss_vulnerability(
        url=args.url,
        threads=args.threads,
        use_advanced=args.advanced
    )
    
    # 输出结果
    print("\n" + "=" * 50)
    if results:
        print(f"[+] 扫描完成！共发现 {len(results)} 个XSS漏洞")
        print("=" * 50)
        
        for i, result in enumerate(results, 1):
            print(f"\n--- 漏洞 {i} ---")
            print(f"URL: {result['url']}")
            print(f"参数: {result['param']}")
            print(f"载荷: {result['payload']}")
            print(f"HTTP状态码: {result['status_code']}")
            print(f"响应长度: {result['response_length']} 字节")
    else:
        print("[-] 未发现XSS漏洞")
        print("=" * 50)
    
    # 保存结果
    if args.output and results:
        with open(args.output, 'w', encoding='utf-8') as f:
            for result in results:
                f.write(f"URL: {result['url']}\n")
                f.write(f"参数: {result['param']}\n")
                f.write(f"载荷: {result['payload']}\n")
                f.write(f"状态码: {result['status_code']}\n")
                f.write(f"响应长度: {result['response_length']} 字节\n\n")
        print(f"\n[+] 结果已保存到: {args.output}")
    
    if not results:
        print("\n[*] 提示：")
        print("    1. 可以尝试使用 --advanced 参数启用更多绕过载荷")
        print("    2. POST参数、Cookie、User-Agent等位置可能存在XSS，需手工测试")


if __name__ == "__main__":
    main()