#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
命令注入漏洞扫描器
支持基于响应的命令注入检测和时间盲注检测
"""

import requests
import argparse
import sys
import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from tqdm import tqdm
import payloads

# 禁用SSL警告
requests.packages.urllib3.disable_warnings()

# ========== 配置 ==========
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

TIMEOUT = 15
TIME_THRESHOLD = 5  # 时间盲注阈值（秒）


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


def check_response_injection(url):
    """
    基于响应的命令注入检测
    注入载荷后检查响应中是否包含命令执行的输出特征
    """
    params = extract_params(url)
    
    if not params:
        print("[!] URL中没有GET参数，无法进行命令注入测试")
        return None
    
    print(f"[*] 检测到 {len(params)} 个参数: {list(params.keys())}")
    print(f"[*] 开始命令注入检测（基于响应）...")
    
    # 先获取正常响应（基线）
    normal_response = None
    try:
        normal_response = requests.get(
            url,
            headers=DEFAULT_HEADERS,
            timeout=TIMEOUT,
            verify=False
        )
    except:
        pass
    
    # 加载载荷
    basic_payloads = payloads.load_payloads("payloads/basic.txt")
    if not basic_payloads:
        basic_payloads = payloads.get_builtin_basic_payloads()
    
    total_tests = len(params) * len(basic_payloads)
    results = []
    
    with tqdm(total=total_tests, desc="命令注入进度", unit="test") as pbar:
        for param_name in params:
            for pl in basic_payloads:
                test_url = inject_param(url, param_name, pl)
                
                try:
                    response = requests.get(
                        test_url,
                        headers=DEFAULT_HEADERS,
                        timeout=TIMEOUT,
                        verify=False
                    )
                    
                    response_text = response.text
                    
                    # 1. 检测已知的命令输出特征
                    for pattern in payloads.COMMAND_SUCCESS_PATTERNS:
                        matches = re.findall(pattern, response_text, re.IGNORECASE)
                        if matches:
                            # 确保正常响应中没有这个特征（排除误报）
                            if normal_response:
                                normal_matches = re.findall(pattern, normal_response.text, re.IGNORECASE)
                                if matches == normal_matches:
                                    continue
                            
                            result = {
                                'url': test_url,
                                'param': param_name,
                                'payload': pl,
                                'type': '基于响应',
                                'evidence': str(matches[0]) if isinstance(matches[0], str) else str(matches[0][0] if isinstance(matches[0], tuple) else matches[0]),
                                'status_code': response.status_code,
                            }
                            results.append(result)
                            
                            tqdm.write(f"\n[+] 发现命令注入漏洞!")
                            tqdm.write(f"    URL: {test_url}")
                            tqdm.write(f"    参数: {param_name}")
                            tqdm.write(f"    载荷: {pl}")
                            tqdm.write(f"    证据: {result['evidence']}")
                            break
                    
                    # 2. 检查echo test123是否反射（通用检测）
                    if 'echo test123' in pl and 'test123' in response_text:
                        if normal_response and 'test123' not in normal_response.text:
                            result = {
                                'url': test_url,
                                'param': param_name,
                                'payload': pl,
                                'type': '基于响应（echo）',
                                'evidence': 'test123',
                                'status_code': response.status_code,
                            }
                            # 检查是否已在结果中
                            if not any(r['url'] == test_url and r['param'] == param_name for r in results):
                                results.append(result)
                                tqdm.write(f"\n[+] 发现命令注入漏洞!")
                                tqdm.write(f"    URL: {test_url}")
                                tqdm.write(f"    参数: {param_name}")
                                tqdm.write(f"    载荷: {pl}")
                                tqdm.write(f"    证据: test123")
                
                except requests.exceptions.RequestException:
                    pass
                
                pbar.update(1)
    
    return results


def check_time_injection(url):
    """
    时间盲注检测
    注入sleep/ping载荷，检测响应时间是否显著增加
    """
    params = extract_params(url)
    
    if not params:
        return None
    
    print(f"\n[*] 开始命令注入检测（时间盲注）...")
    
    # 先测量正常响应时间
    normal_time = 0
    try:
        start = time.time()
        requests.get(url, headers=DEFAULT_HEADERS, timeout=TIMEOUT, verify=False)
        normal_time = time.time() - start
    except:
        normal_time = 1
    
    print(f"[*] 正常响应时间: {normal_time:.2f}秒")
    print(f"[*] 时间盲注阈值: {TIME_THRESHOLD}秒")
    
    # 加载载荷
    time_payloads = payloads.load_payloads("payloads/time_based.txt")
    if not time_payloads:
        time_payloads = payloads.get_builtin_time_payloads()
    
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
                    
                    # 如果响应时间超过阈值且明显大于正常时间
                    if elapsed_time >= TIME_THRESHOLD and elapsed_time > normal_time * 2:
                        result = {
                            'url': test_url,
                            'param': param_name,
                            'payload': pl,
                            'type': '时间盲注',
                            'response_time': round(elapsed_time, 2),
                            'normal_time': round(normal_time, 2),
                            'status_code': response.status_code,
                        }
                        results.append(result)
                        
                        tqdm.write(f"\n[+] 发现命令注入漏洞（时间盲注）!")
                        tqdm.write(f"    URL: {test_url}")
                        tqdm.write(f"    参数: {param_name}")
                        tqdm.write(f"    载荷: {pl}")
                        tqdm.write(f"    响应时间: {elapsed_time:.2f}秒 (正常: {normal_time:.2f}秒)")
                
                except requests.exceptions.RequestException:
                    pass
                
                pbar.update(1)
    
    return results


def main():
    """
    命令行入口
    """
    parser = argparse.ArgumentParser(
        description="命令注入漏洞扫描器 - 检测GET参数中的命令注入漏洞",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python scanner.py -u "http://test.com/ping.php?ip=127.0.0.1"
  python scanner.py -u "http://test.com/cmd.php?cmd=ls"
  python scanner.py -u "http://test.com/ping.php?ip=127.0.0.1" --no-time
  python scanner.py -u "http://test.com/ping.php?ip=127.0.0.1" --no-response
  python scanner.py -u "http://test.com/ping.php?ip=127.0.0.1" --time-threshold 10
  python scanner.py -u "http://test.com/ping.php?ip=127.0.0.1" -o result.txt
        """
    )
    
    parser.add_argument("-u", "--url", required=True,
                        help="目标URL（包含参数）")
    parser.add_argument("-o", "--output",
                        help="结果输出文件路径")
    parser.add_argument("--no-response", action="store_true",
                        help="跳过基于响应的检测")
    parser.add_argument("--no-time", action="store_true",
                        help="跳过时间盲注检测")
    parser.add_argument("--time-threshold", type=int, default=5,
                        help="时间盲注阈值（秒），默认5秒")
    
    args = parser.parse_args()
    
    global TIME_THRESHOLD
    TIME_THRESHOLD = args.time_threshold
    
    print("=" * 50)
    print("命令注入漏洞扫描器")
    print("=" * 50)
    print(f"[*] 目标URL: {args.url}")
    print(f"[*] 时间盲注阈值: {TIME_THRESHOLD}秒")
    print()
    
    all_results = []
    
    # 基于响应的检测
    if not args.no_response:
        response_results = check_response_injection(args.url)
        if response_results:
            all_results.extend(response_results)
        else:
            print("\n[-] 未发现命令注入漏洞（基于响应）")
    
    # 时间盲注检测
    if not args.no_time:
        time_results = check_time_injection(args.url)
        if time_results:
            all_results.extend(time_results)
        else:
            print("\n[-] 未发现命令注入漏洞（时间盲注）")
    
    # 汇总结果
    print("\n" + "=" * 50)
    print(f"[+] 扫描完成！共发现 {len(all_results)} 个命令注入漏洞")
    print("=" * 50)
    
    for i, result in enumerate(all_results, 1):
        print(f"\n--- 漏洞 {i} ---")
        print(f"类型: {result['type']}")
        print(f"URL: {result['url']}")
        print(f"参数: {result['param']}")
        print(f"载荷: {result['payload']}")
        if result['type'] == '时间盲注':
            print(f"响应时间: {result['response_time']}秒 (正常: {result['normal_time']}秒)")
        else:
            print(f"证据: {result['evidence']}")
        print(f"HTTP状态码: {result['status_code']}")
    
    # 保存结果
    if args.output and all_results:
        with open(args.output, 'w', encoding='utf-8') as f:
            for result in all_results:
                f.write(f"[{result['type']}] {result['url']}\n")
                f.write(f"  参数: {result['param']}\n")
                f.write(f"  载荷: {result['payload']}\n")
                if result['type'] == '时间盲注':
                    f.write(f"  响应时间: {result['response_time']}秒\n")
                else:
                    f.write(f"  证据: {result['evidence']}\n")
                f.write("\n")
        print(f"\n[+] 结果已保存到: {args.output}")
    
    if not all_results:
        print("\n[*] 提示：")
        print("    1. 命令注入可能存在于POST参数、Cookie、HTTP头中")
        print("    2. 目标可能过滤了特殊字符，需尝试其他绕过方式")
        print("    3. 可以尝试增加 --time-threshold 调整检测灵敏度")


if __name__ == "__main__":
    main()