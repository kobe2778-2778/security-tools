#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQL注入漏洞扫描器
支持报错注入检测和时间盲注检测
"""

import requests
import argparse
import sys
import time
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

TIMEOUT = 15  # 请求超时时间
TIME_THRESHOLD = 5  # 时间盲注阈值（秒）

# 常见的SQL错误特征
ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_.*",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_.*",
    r"valid PostgreSQL result",
    r"ORA-[0-9]{5}",
    r"Oracle error",
    r"Oracle.*Driver",
    r"SQLite/JDBCDriver",
    r"SQLite.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"Warning.*sqlite_.*",
    r"valid SQLite result",
    r"SQL Server.*Driver",
    r"Driver.*SQL Server",
    r"SQLServer JDBC Driver",
    r"com\.microsoft\.sqlserver",
    r"Unclosed quotation mark after the character string",
    r"Microsoft OLE DB Provider for ODBC Drivers",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Incorrect syntax near",
    r"Syntax error in string in query expression",
    r"Unclosed quotation mark",
    r"quoted string not properly terminated",
    r"SQL command not properly ended",
    r"division by zero",
    r"Unknown column",
    r"Table.*doesn't exist",
    r"Column.*not found",
    r"Column count.*doesn't match",
    r"You have an error in your SQL syntax",
]


def extract_params(url):
    """
    从URL中提取GET参数
    例如: http://test.com/page.php?id=1&name=admin
    返回: {'id': '1', 'name': 'admin'}
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    # parse_qs 返回的是列表，转成单值
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


def check_error_injection(url):
    """
    报错注入检测
    逐个参数注入载荷，检测响应中是否包含SQL错误信息
    """
    params = extract_params(url)
    
    if not params:
        print("[!] URL中没有GET参数，无法进行SQL注入测试")
        return None
    
    print(f"[*] 检测到 {len(params)} 个参数: {list(params.keys())}")
    print(f"[*] 开始报错注入检测...")
    
    # 加载载荷
    error_payloads = payloads.load_payloads_from_file("payloads/error_based.txt")
    if not error_payloads:
        error_payloads = payloads.get_default_error_payloads()
    
    total_tests = len(params) * len(error_payloads)
    results = []
    
    with tqdm(total=total_tests, desc="报错注入进度", unit="test") as pbar:
        for param_name in params:
            for pl in error_payloads:
                test_url = inject_param(url, param_name, pl)
                
                try:
                    response = requests.get(
                        test_url,
                        headers=DEFAULT_HEADERS,
                        timeout=TIMEOUT,
                        verify=False
                    )
                    
                    # 检测响应中是否包含SQL错误特征
                    for pattern in ERROR_PATTERNS:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            result = {
                                'url': test_url,
                                'param': param_name,
                                'payload': pl,
                                'type': '报错注入',
                                'pattern': pattern,
                                'status_code': response.status_code,
                            }
                            results.append(result)
                            tqdm.write(f"\n[+] 发现SQL注入漏洞: {test_url}")
                            tqdm.write(f"    参数: {param_name}, 载荷: {pl}")
                            tqdm.write(f"    匹配特征: {pattern}")
                            break
                            
                except requests.exceptions.RequestException:
                    pass
                
                pbar.update(1)
    
    return results


def check_time_injection(url):
    """
    时间盲注检测
    逐个参数注入时间盲注载荷，检测响应时间是否显著增加
    """
    params = extract_params(url)
    
    if not params:
        return None
    
    print(f"\n[*] 开始时间盲注检测...")
    
    # 加载载荷
    time_payloads = payloads.load_payloads_from_file("payloads/time_based.txt")
    if not time_payloads:
        time_payloads = payloads.get_default_time_payloads()
    
    total_tests = len(params) * len(time_payloads)
    results = []
    
    with tqdm(total=total_tests, desc="时间盲注进度", unit="test") as pbar:
        for param_name in params:
            for pl in time_payloads:
                test_url = inject_param(url, param_name, pl)
                
                try:
                    start_time = time.time()
                    response = requests.get(
                        test_url,
                        headers=DEFAULT_HEADERS,
                        timeout=TIMEOUT,
                        verify=False
                    )
                    elapsed_time = time.time() - start_time
                    
                    # 如果响应时间超过阈值，判定为存在时间盲注
                    if elapsed_time >= TIME_THRESHOLD:
                        result = {
                            'url': test_url,
                            'param': param_name,
                            'payload': pl,
                            'type': '时间盲注',
                            'response_time': round(elapsed_time, 2),
                            'status_code': response.status_code,
                        }
                        results.append(result)
                        tqdm.write(f"\n[+] 发现时间盲注漏洞: {test_url}")
                        tqdm.write(f"    参数: {param_name}, 载荷: {pl}")
                        tqdm.write(f"    响应时间: {elapsed_time:.2f}秒")
                        
                except requests.exceptions.RequestException:
                    pass
                
                pbar.update(1)
    
    return results


def main():
    """
    命令行入口
    """
    parser = argparse.ArgumentParser(
        description="SQL注入漏洞扫描器 - 检测GET参数中的SQL注入漏洞",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python scanner.py -u "http://test.com/page.php?id=1"
  python scanner.py -u "http://test.com/page.php?id=1&name=admin"
  python scanner.py -u "http://test.com/page.php?id=1" --no-error
  python scanner.py -u "http://test.com/page.php?id=1" --no-time
  python scanner.py -u "http://test.com/page.php?id=1" -o result.txt
        """
    )
    
    parser.add_argument("-u", "--url", required=True,
                        help="目标URL（包含参数），例如 http://test.com/page.php?id=1")
    parser.add_argument("-o", "--output",
                        help="结果输出文件路径")
    parser.add_argument("--no-error", action="store_true",
                        help="跳过报错注入检测")
    parser.add_argument("--no-time", action="store_true",
                        help="跳过时间盲注检测")
    parser.add_argument("--time-threshold", type=int, default=5,
                        help="时间盲注阈值（秒），默认5秒")
    
    args = parser.parse_args()
    
    global TIME_THRESHOLD
    TIME_THRESHOLD = args.time_threshold
    
    print("=" * 50)
    print("SQL注入漏洞扫描器")
    print("=" * 50)
    print(f"[*] 目标URL: {args.url}")
    print(f"[*] 时间盲注阈值: {TIME_THRESHOLD}秒")
    print()
    
    all_results = []
    
    # 报错注入检测
    if not args.no_error:
        error_results = check_error_injection(args.url)
        if error_results:
            all_results.extend(error_results)
        else:
            print("\n[-] 未发现报错注入漏洞")
    
    # 时间盲注检测
    if not args.no_time:
        time_results = check_time_injection(args.url)
        if time_results:
            all_results.extend(time_results)
        else:
            print("\n[-] 未发现时间盲注漏洞")
    
    # 汇总结果
    print("\n" + "=" * 50)
    print(f"[+] 扫描完成！共发现 {len(all_results)} 个SQL注入漏洞")
    print("=" * 50)
    
    for i, result in enumerate(all_results, 1):
        print(f"\n--- 漏洞 {i} ---")
        print(f"类型: {result['type']}")
        print(f"URL: {result['url']}")
        print(f"参数: {result['param']}")
        print(f"载荷: {result['payload']}")
        if result['type'] == '报错注入':
            print(f"匹配特征: {result['pattern']}")
        elif result['type'] == '时间盲注':
            print(f"响应时间: {result['response_time']}秒")
        print(f"HTTP状态码: {result['status_code']}")
    
    # 保存结果
    if args.output and all_results:
        with open(args.output, 'w', encoding='utf-8') as f:
            for result in all_results:
                f.write(f"[{result['type']}] {result['url']}\n")
                f.write(f"  参数: {result['param']}, 载荷: {result['payload']}\n\n")
        print(f"\n[+] 结果已保存到: {args.output}")
    
    if not all_results:
        print("\n[*] 提示：如果目标确实存在SQL注入，可能需要调整载荷或使用更高级的测试方法")


if __name__ == "__main__":
    main()