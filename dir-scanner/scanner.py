#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
目录/文件爆破扫描器
用于发现Web服务器上隐藏的目录和文件
"""

import requests
import threading
import queue
import argparse
import sys
import os
from urllib.parse import urljoin
from tqdm import tqdm

# 禁用requests的SSL警告（扫描内网自签名站点时有用）
requests.packages.urllib3.disable_warnings()

# ========== 配置区 ==========
# 默认的HTTP请求头，伪装成正常浏览器
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
}

# 默认的超时时间（秒）
TIMEOUT = 8

# 忽略这些常见的"不存在"状态码和内容
DEFAULT_IGNORE_CODES = [404]


def load_wordlist(file_path):
    """
    从文件加载字典，逐行读取并去除空白字符
    返回路径列表
    """
    if not os.path.exists(file_path):
        print(f"[!] 错误：字典文件不存在 -> {file_path}")
        sys.exit(1)
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        paths = [line.strip() for line in f if line.strip()]
    
    print(f"[+] 成功加载字典，共 {len(paths)} 条路径")
    return paths


def make_url(base, path):
    """
    拼接基础URL和路径，确保不会出现双斜杠等问题
    例如: base=http://test.com/ , path=/admin -> http://test.com/admin
    """
    # 移除路径开头的斜杠，因为urljoin会正确处理
    if path.startswith('/'):
        path = path[1:]
    return urljoin(base, path)


def worker(task_queue, result_queue, base_url, status_filter, extensions, progress_bar):
    """
    消费者线程：不断从任务队列取任务，发包扫描，结果放入结果队列
    """
    while True:
        try:
            # 从队列获取一个任务，超时3秒后退出
            path = task_queue.get(timeout=3)
        except queue.Empty:
            # 队列空了，线程退出
            return
        
        # 构造要扫描的URL列表
        # 1. 原始路径
        urls_to_test = [make_url(base_url, path)]
        
        # 2. 如果用户指定了后缀名，为每个路径追加后缀
        if extensions:
            for ext in extensions:
                # 确保后缀以点开头
                if not ext.startswith('.'):
                    ext = '.' + ext
                urls_to_test.append(make_url(base_url, path + ext))
        
        # 逐个测试构造好的URL
        for test_url in urls_to_test:
            try:
                response = requests.get(
                    test_url,
                    headers=DEFAULT_HEADERS,
                    timeout=TIMEOUT,
                    verify=False,  # 忽略SSL证书错误
                    allow_redirects=False  # 不自动跟随跳转
                )
                status_code = response.status_code
                
                # 判断是否是有效发现
                if status_filter:
                    # 用户指定了状态码过滤
                    if status_code in status_filter:
                        result_queue.put((status_code, test_url))
                else:
                    # 默认：不是404就算发现
                    if status_code not in DEFAULT_IGNORE_CODES:
                        result_queue.put((status_code, test_url))
                        
            except requests.exceptions.RequestException:
                # 连接错误、超时等，静默处理
                pass
        
        # 更新进度条
        progress_bar.update(1)
        task_queue.task_done()


def run_scan(base_url, wordlist, threads=30, extensions=None, status_filter=None, output_file=None):
    """
    主扫描函数
    """
    # 确保base_url以http://或https://开头
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'http://' + base_url
        print(f"[*] 未指定协议，默认使用 http://，完整URL: {base_url}")
    
    # 确保base_url以/结尾
    if not base_url.endswith('/'):
        base_url += '/'
    
    # 加载字典
    paths = load_wordlist(wordlist)
    
    # 创建任务队列和结果队列
    task_queue = queue.Queue()
    result_queue = queue.Queue()
    
    # 将所有路径放入任务队列
    for p in paths:
        task_queue.put(p)
    
    total_tasks = len(paths)
    
    print(f"[*] 开始扫描目标: {base_url}")
    print(f"[*] 线程数: {threads}")
    print(f"[*] 总任务数: {total_tasks}")
    if extensions:
        print(f"[*] 后缀名: {extensions}")
    print("-" * 50)
    
    # 创建进度条
    progress_bar = tqdm(total=total_tasks, desc="扫描进度", unit="path")
    
    # 创建并启动消费者线程
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(
            target=worker,
            args=(task_queue, result_queue, base_url, status_filter, extensions, progress_bar)
        )
        t.daemon = True  # 守护线程，主程序退出时自动结束
        t.start()
        thread_list.append(t)
    
    # 等待所有任务完成
    task_queue.join()
    progress_bar.close()
    
    # 收集所有结果
    results = []
    while not result_queue.empty():
        results.append(result_queue.get())
    
    # 按状态码排序，方便查看
    results.sort(key=lambda x: x[0])
    
    # 输出结果
    print("\n" + "=" * 50)
    print(f"[+] 扫描完成！共发现 {len(results)} 个有效路径：")
    print("=" * 50)
    
    for status_code, url in results:
        print(f"  [{status_code}] {url}")
    
    # 如果指定了输出文件，保存结果
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            for _, url in results:
                f.write(url + '\n')
        print(f"\n[+] 结果已保存到: {output_file}")
    
    return results


def main():
    """
    命令行入口，解析参数并启动扫描
    """
    parser = argparse.ArgumentParser(
        description="目录/文件爆破扫描器 - 发现Web服务器隐藏路径",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python scanner.py -u http://test.com -w wordlists/common.txt
  python scanner.py -u http://test.com -w wordlists/common.txt -t 50
  python scanner.py -u http://test.com -w wordlists/common.txt -e php,asp,txt
  python scanner.py -u http://test.com -w wordlists/common.txt -mc 200,301,403 -o result.txt
        """
    )
    
    parser.add_argument("-u", "--url", required=True,
                        help="目标URL，例如 http://example.com")
    parser.add_argument("-w", "--wordlist", required=True,
                        help="字典文件路径")
    parser.add_argument("-t", "--threads", type=int, default=30,
                        help="线程数量 (默认: 30)")
    parser.add_argument("-e", "--extensions",
                        help="文件后缀名，用逗号分隔，例如: php,asp,txt")
    parser.add_argument("-mc", "--match-codes",
                        help="要匹配的HTTP状态码，用逗号分隔，例如: 200,301,403")
    parser.add_argument("-o", "--output",
                        help="结果输出文件路径")
    
    args = parser.parse_args()
    
    # 处理后缀名参数
    extensions_list = None
    if args.extensions:
        extensions_list = [e.strip() for e in args.extensions.split(',')]
    
    # 处理状态码过滤参数
    status_filter = None
    if args.match_codes:
        status_filter = [int(c.strip()) for c in args.match_codes.split(',')]
    
    # 开始扫描
    run_scan(
        base_url=args.url,
        wordlist=args.wordlist,
        threads=args.threads,
        extensions=extensions_list,
        status_filter=status_filter,
        output_file=args.output
    )


if __name__ == "__main__":
    main()