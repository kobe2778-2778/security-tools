#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
线程URL检查器
多线程高速检测URL存活状态
"""

import argparse
import concurrent.futures
import logging
import sys
import time
from dataclasses import dataclass
from typing import Optional

import requests
from tqdm import tqdm

requests.packages.urllib3.disable_warnings()

DEFAULT_TIMEOUT = 8
DEFAULT_THREADS = 30
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(levelname)s] %(message)s")


@dataclass
class URLResult:
    """URL检测结果"""
    url: str
    status_code: int = 0
    error: Optional[str] = None
    response_time: float = 0.0
    response_length: int = 0

    @property
    def is_alive(self) -> bool:
        return 200 <= self.status_code < 500

    def __str__(self) -> str:
        if self.is_alive:
            return f"[{self.status_code}] {self.url} ({self.response_time:.1f}s)"
        return f"[错误] {self.url} -> {self.error}"


@dataclass
class ThreadedCheckerConfig:
    """检查器配置"""
    url_file: str
    threads: int = DEFAULT_THREADS
    timeout: int = DEFAULT_TIMEOUT
    output_file: Optional[str] = None


class ThreadedURLChecker:
    """线程URL检查器"""

    def __init__(self, config: ThreadedCheckerConfig):
        self.config = config
        self.results: list[URLResult] = []

    def _load_urls(self) -> list:
        """加载URL列表"""
        try:
            with open(self.config.url_file, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"[!] 文件不存在: {self.config.url_file}")
            sys.exit(1)

    def _check_url(self, url: str) -> URLResult:
        """检查单个URL"""
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        try:
            start = time.time()
            response = requests.get(
                url,
                headers=DEFAULT_HEADERS,
                timeout=self.config.timeout,
                verify=False,
                allow_redirects=True,
            )
            elapsed = time.time() - start
            return URLResult(
                url=url,
                status_code=response.status_code,
                response_time=round(elapsed, 2),
                response_length=len(response.text),
            )
        except requests.exceptions.RequestException as e:
            logging.debug(f"请求失败 {url}: {e}")
            return URLResult(url=url, error=str(e)[:100])

    def check(self) -> list[URLResult]:
        """开始多线程检查"""
        urls = self._load_urls()
        print(f"[*] 加载 {len(urls)} 个URL")
        print(f"[*] 线程数: {self.config.threads}\n")

        with tqdm(total=len(urls), desc="检查进度", unit="个") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                future_map = {executor.submit(self._check_url, url): url for url in urls}
                for future in concurrent.futures.as_completed(future_map):
                    result = future.result()
                    self.results.append(result)
                    if result.is_alive:
                        tqdm.write(f"[+] {result}")
                    pbar.update(1)

        self.results.sort(key=lambda r: r.status_code, reverse=True)
        return self.results

    def print_summary(self) -> None:
        """打印摘要"""
        alive = [r for r in self.results if r.is_alive]
        print(f"\n{'=' * 50}")
        print(f"[+] 检查完成！存活: {len(alive)}/{len(self.results)}")

    def save_results(self) -> None:
        """保存结果"""
        if not self.config.output_file:
            return
        try:
            with open(self.config.output_file, "w", encoding="utf-8") as f:
                for result in self.results:
                    if result.is_alive:
                        f.write(f"{result.url}\n")
            print(f"\n[+] 存活URL已保存到: {self.config.output_file}")
        except OSError as e:
            print(f"\n[!] 保存失败: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="线程URL检查器 - 多线程高速检测URL存活")
    parser.add_argument("-f", "--file", required=True, help="URL列表文件")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help=f"线程数（默认{DEFAULT_THREADS}）")
    parser.add_argument("-o", "--output", help="输出文件")

    args = parser.parse_args()

    config = ThreadedCheckerConfig(
        url_file=args.file,
        threads=args.threads,
        output_file=args.output,
    )

    print("=" * 50)
    print("线程URL检查器")
    print("=" * 50)

    checker = ThreadedURLChecker(config)
    checker.check()
    checker.print_summary()
    checker.save_results()


if __name__ == "__main__":
    main()
