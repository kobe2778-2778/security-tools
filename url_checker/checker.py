#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
URL检查器
批量检测URL的可访问性
"""

import argparse
import logging
import sys
from dataclasses import dataclass
from typing import Optional

import requests
from tqdm import tqdm

requests.packages.urllib3.disable_warnings()

DEFAULT_TIMEOUT = 8
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(levelname)s] %(message)s")


@dataclass
class URLCheckResult:
    """URL检查结果"""
    url: str
    status_code: int = 0
    error: Optional[str] = None
    response_length: int = 0
    response_time: float = 0.0

    @property
    def is_alive(self) -> bool:
        return 200 <= self.status_code < 500

    def __str__(self) -> str:
        if self.status_code > 0:
            return f"[{self.status_code}] {self.url} ({self.response_length}字节, {self.response_time:.1f}s)"
        return f"[错误] {self.url} -> {self.error}"


@dataclass
class CheckerConfig:
    """检查器配置"""
    url_file: str
    timeout: int = DEFAULT_TIMEOUT
    output_file: Optional[str] = None


class URLChecker:
    """URL检查器"""

    def __init__(self, config: CheckerConfig):
        self.config = config
        self.results: list[URLCheckResult] = []

    def _load_urls(self) -> list:
        """加载URL列表"""
        try:
            with open(self.config.url_file, "r", encoding="utf-8", errors="ignore") as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                for url in urls:
                    if not url.startswith(("http://", "https://")):
                        url = "http://" + url
                return urls
        except FileNotFoundError:
            print(f"[!] 文件不存在: {self.config.url_file}")
            sys.exit(1)

    def _check_url(self, url: str) -> URLCheckResult:
        """检查单个URL"""
        import time
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
            return URLCheckResult(
                url=url,
                status_code=response.status_code,
                response_length=len(response.text),
                response_time=round(elapsed, 2),
            )
        except requests.exceptions.RequestException as e:
            logging.debug(f"请求失败 {url}: {e}")
            return URLCheckResult(url=url, error=str(e)[:100])

    def check(self) -> list[URLCheckResult]:
        """开始检查"""
        urls = self._load_urls()
        print(f"[*] 加载 {len(urls)} 个URL\n")

        for url in tqdm(urls, desc="检查进度", unit="个"):
            result = self._check_url(url)
            self.results.append(result)
            if result.is_alive:
                tqdm.write(f"[+] {result}")
            else:
                tqdm.write(f"[-] {result}")

        return self.results

    def print_summary(self) -> None:
        """打印摘要"""
        alive = [r for r in self.results if r.is_alive]
        dead = len(self.results) - len(alive)
        print(f"\n{'=' * 50}")
        print(f"[+] 检查完成！存活: {len(alive)}, 不可达: {dead}")

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
    parser = argparse.ArgumentParser(description="URL检查器 - 批量检测URL存活")
    parser.add_argument("-f", "--file", required=True, help="包含URL列表的文件")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"超时时间（默认{DEFAULT_TIMEOUT}秒）")
    parser.add_argument("-o", "--output", help="输出文件")

    args = parser.parse_args()

    config = CheckerConfig(
        url_file=args.file,
        timeout=args.timeout,
        output_file=args.output,
    )

    print("=" * 50)
    print("URL检查器")
    print("=" * 50)

    checker = URLChecker(config)
    checker.check()
    checker.print_summary()
    checker.save_results()


if __name__ == "__main__":
    main()
