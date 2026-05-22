#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
子域名查找器
通过字典爆破和DNS查询发现目标子域名
"""

import argparse
import concurrent.futures
import logging
import socket
import sys
from dataclasses import dataclass, field
from typing import Optional

from tqdm import tqdm

DEFAULT_TIMEOUT = 3
DEFAULT_THREADS = 50

logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(levelname)s] %(message)s")


@dataclass
class SubdomainResult:
    """子域名查询结果"""
    subdomain: str
    ip_address: Optional[str] = None
    error: Optional[str] = None

    @property
    def is_alive(self) -> bool:
        return self.ip_address is not None

    def __str__(self) -> str:
        if self.is_alive:
            return f"{self.subdomain} -> {self.ip_address}"
        return f"{self.subdomain} -> 未解析"


@dataclass
class FinderConfig:
    """查找器配置"""
    domain: str
    wordlist: str
    threads: int = DEFAULT_THREADS
    timeout: int = DEFAULT_TIMEOUT
    output_file: Optional[str] = None


class SubdomainFinder:
    """子域名查找器"""

    def __init__(self, config: FinderConfig):
        self.config = config
        self.results: list[SubdomainResult] = []

    def _load_wordlist(self) -> list:
        """加载字典文件"""
        try:
            with open(self.config.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"[!] 字典文件不存在: {self.config.wordlist}")
            sys.exit(1)

    def _resolve(self, subdomain: str) -> SubdomainResult:
        """解析单个子域名"""
        fqdn = f"{subdomain}.{self.config.domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return SubdomainResult(subdomain=fqdn, ip_address=ip)
        except socket.gaierror as e:
            logging.debug(f"解析失败 {fqdn}: {e}")
            return SubdomainResult(subdomain=fqdn, error=str(e))

    def find(self) -> list[SubdomainResult]:
        """开始查找"""
        wordlist = self._load_wordlist()
        print(f"[*] 字典加载完成，共 {len(wordlist)} 个前缀")
        print(f"[*] 目标域名: {self.config.domain}")
        print(f"[*] 线程数: {self.config.threads}\n")

        with tqdm(total=len(wordlist), desc="扫描进度", unit="个") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                futures = {executor.submit(self._resolve, sub): sub for sub in wordlist}
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result.is_alive:
                        self.results.append(result)
                        tqdm.write(f"[+] {result}")
                    pbar.update(1)

        self.results.sort(key=lambda r: r.subdomain)
        return self.results

    def print_summary(self) -> None:
        """打印结果摘要"""
        alive = [r for r in self.results if r.is_alive]
        print(f"\n{'=' * 50}")
        print(f"[+] 扫描完成！共找到 {len(alive)} 个子域名")
        print("=" * 50)
        for result in alive:
            print(f"  {result}")

    def save_results(self) -> None:
        """保存结果到文件"""
        if not self.config.output_file or not self.results:
            return
        try:
            with open(self.config.output_file, "w", encoding="utf-8") as f:
                for result in self.results:
                    if result.is_alive:
                        f.write(f"{result.subdomain}\n")
            print(f"\n[+] 结果已保存到: {self.config.output_file}")
        except OSError as e:
            print(f"\n[!] 保存失败: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="子域名查找器 - DNS字典爆破")
    parser.add_argument("-d", "--domain", required=True, help="目标域名")
    parser.add_argument("-w", "--wordlist", required=True, help="字典文件路径")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help=f"线程数（默认{DEFAULT_THREADS}）")
    parser.add_argument("-o", "--output", help="输出文件路径")

    args = parser.parse_args()

    config = FinderConfig(
        domain=args.domain.rstrip("."),
        wordlist=args.wordlist,
        threads=args.threads,
        output_file=args.output,
    )

    print("=" * 50)
    print("子域名查找器")
    print("=" * 50)

    finder = SubdomainFinder(config)
    finder.find()
    finder.print_summary()
    finder.save_results()


if __name__ == "__main__":
    main()
