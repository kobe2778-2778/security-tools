#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
目录扫描器
多线程Web目录文件爆破，发现隐藏路径
"""

import argparse
import logging
import os
import sys
import threading
import queue
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin

import requests
from tqdm import tqdm

import payloads

requests.packages.urllib3.disable_warnings()

DEFAULT_THREADS = 30
DEFAULT_TIMEOUT = 8
DEFAULT_IGNORE_CODES = [404]

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
}

logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(levelname)s] %(message)s")


@dataclass
class DirScanResult:
    """目录扫描结果"""
    url: str
    status_code: int
    response_length: int = 0

    def __str__(self) -> str:
        return f"[{self.status_code}] {self.url} ({self.response_length}字节)"


@dataclass
class DirScannerConfig:
    """扫描器配置"""
    url: str
    wordlist: str
    threads: int = DEFAULT_THREADS
    extensions: Optional[list] = None
    status_filter: Optional[list] = None
    timeout: int = DEFAULT_TIMEOUT
    output_file: Optional[str] = None


class DirScanner:
    """目录扫描器"""

    def __init__(self, config: DirScannerConfig):
        self.config = config
        self.results: list[DirScanResult] = []
        self._lock = threading.Lock()

    def _normalize_url(self, url: str) -> str:
        """规范化URL"""
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        if not url.endswith("/"):
            url += "/"
        return url

    def _load_wordlist(self) -> list:
        """加载字典"""
        try:
            with open(self.config.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"[!] 字典文件不存在: {self.config.wordlist}")
            sys.exit(1)

    def _make_urls(self, base_url: str, path: str) -> list:
        """构造测试URL列表"""
        urls = [urljoin(base_url, path.lstrip("/"))]
        if self.config.extensions:
            for ext in self.config.extensions:
                ext = ext if ext.startswith(".") else f".{ext}"
                urls.append(urljoin(base_url, (path + ext).lstrip("/")))
        return urls

    def _should_record(self, status_code: int) -> bool:
        """判断是否记录该状态码"""
        if self.config.status_filter:
            return status_code in self.config.status_filter
        return status_code not in DEFAULT_IGNORE_CODES

    def _worker(self, task_queue: queue.Queue, progress_bar: tqdm) -> None:
        """消费者线程"""
        base_url = self._normalize_url(self.config.url)
        while True:
            try:
                path = task_queue.get(timeout=3)
            except queue.Empty:
                return

            for test_url in self._make_urls(base_url, path):
                try:
                    response = requests.get(
                        test_url,
                        headers=DEFAULT_HEADERS,
                        timeout=self.config.timeout,
                        verify=False,
                        allow_redirects=False,
                    )
                    if self._should_record(response.status_code):
                        result = DirScanResult(
                            url=test_url,
                            status_code=response.status_code,
                            response_length=len(response.text),
                        )
                        with self._lock:
                            self.results.append(result)
                        tqdm.write(f"[+] {result}")
                except requests.exceptions.RequestException as e:
                    logging.debug(f"请求失败 {test_url}: {e}")

            progress_bar.update(1)
            task_queue.task_done()

    def scan(self) -> list[DirScanResult]:
        """开始扫描"""
        base_url = self._normalize_url(self.config.url)
        paths = self._load_wordlist()

        print(f"[*] 目标URL: {base_url}")
        print(f"[*] 字典数量: {len(paths)}")
        print(f"[*] 线程数: {self.config.threads}")
        if self.config.extensions:
            print(f"[*] 后缀名: {self.config.extensions}")
        print()

        task_queue = queue.Queue()
        for path in paths:
            task_queue.put(path)

        with tqdm(total=len(paths), desc="扫描进度", unit="个") as pbar:
            threads = []
            for _ in range(self.config.threads):
                t = threading.Thread(target=self._worker, args=(task_queue, pbar))
                t.daemon = True
                t.start()
                threads.append(t)

            task_queue.join()
            for t in threads:
                t.join()

        self.results.sort(key=lambda r: r.status_code)
        return self.results

    def print_summary(self) -> None:
        """打印摘要"""
        print(f"\n{'=' * 50}")
        print(f"[+] 扫描完成！共发现 {len(self.results)} 个有效路径")
        print("=" * 50)
        for result in self.results:
            print(f"  {result}")

    def save_results(self) -> None:
        """保存结果"""
        if not self.config.output_file:
            return
        try:
            with open(self.config.output_file, "w", encoding="utf-8") as f:
                for result in self.results:
                    f.write(f"{result.url}\n")
            print(f"\n[+] 结果已保存到: {self.config.output_file}")
        except OSError as e:
            print(f"\n[!] 保存失败: {e}")


def build_parser() -> argparse.ArgumentParser:
    """构建参数解析器"""
    parser = argparse.ArgumentParser(
        description="目录扫描器 - 多线程Web目录文件爆破",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python scanner.py -u http://test.com -w wordlists/common.txt
  python scanner.py -u http://test.com -w wordlists/common.txt -t 50 -e php,asp
  python scanner.py -u http://test.com -w wordlists/common.txt -mc 200,301,403 -o result.txt
        """,
    )
    parser.add_argument("-u", "--url", required=True, help="目标URL")
    parser.add_argument("-w", "--wordlist", required=True, help="字典文件路径")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help=f"线程数（默认{DEFAULT_THREADS}）")
    parser.add_argument("-e", "--extensions", help="文件后缀名，逗号分隔")
    parser.add_argument("-mc", "--match-codes", help="匹配的状态码，逗号分隔")
    parser.add_argument("-o", "--output", help="输出文件路径")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    extensions = [e.strip() for e in args.extensions.split(",")] if args.extensions else None
    status_filter = [int(c.strip()) for c in args.match_codes.split(",")] if args.match_codes else None

    config = DirScannerConfig(
        url=args.url,
        wordlist=args.wordlist,
        threads=args.threads,
        extensions=extensions,
        status_filter=status_filter,
        output_file=args.output,
    )

    print("=" * 50)
    print("目录扫描器")
    print("=" * 50)

    scanner = DirScanner(config)
    scanner.scan()
    scanner.print_summary()
    scanner.save_results()


if __name__ == "__main__":
    main()
