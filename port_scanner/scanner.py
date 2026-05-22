#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端口扫描器
扫描目标主机的开放TCP端口
"""

import argparse
import concurrent.futures
import logging
import socket
from dataclasses import dataclass, field
from typing import Optional

from tqdm import tqdm

DEFAULT_TIMEOUT = 2
DEFAULT_THREADS = 100
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]

logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(levelname)s] %(message)s")


@dataclass
class PortResult:
    """端口扫描结果"""
    host: str
    port: int
    is_open: bool = False
    service: Optional[str] = None

    def __str__(self) -> str:
        service_info = f" ({self.service})" if self.service else ""
        status = "开放" if self.is_open else "关闭"
        return f"端口 {self.port}: {status}{service_info}"


@dataclass
class PortScannerConfig:
    """扫描器配置"""
    host: str
    ports: list[int] = field(default_factory=lambda: COMMON_PORTS)
    threads: int = DEFAULT_THREADS
    timeout: int = DEFAULT_TIMEOUT
    output_file: Optional[str] = None


class PortScanner:
    """端口扫描器"""

    SERVICE_MAP = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 135: "MSRPC",
        139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
    }

    def __init__(self, config: PortScannerConfig):
        self.config = config
        self.results: list[PortResult] = []

    @classmethod
    def parse_ports(cls, port_str: str) -> list[int]:
        """解析端口字符串，如 1-1000 或 80,443,8080"""
        ports = set()
        for part in port_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.update(range(int(start), int(end) + 1))
            elif part.isdigit():
                ports.add(int(part))
        return sorted(ports)

    def _scan_port(self, port: int) -> PortResult:
        """扫描单个端口"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            result_code = sock.connect_ex((self.config.host, port))
            sock.close()

            is_open = result_code == 0
            service = self.SERVICE_MAP.get(port) if is_open else None
            return PortResult(host=self.config.host, port=port, is_open=is_open, service=service)
        except socket.error as e:
            logging.debug(f"扫描失败 {self.config.host}:{port} - {e}")
            return PortResult(host=self.config.host, port=port)

    def scan(self) -> list[PortResult]:
        """开始扫描"""
        print(f"[*] 目标主机: {self.config.host}")
        print(f"[*] 端口数量: {len(self.config.ports)}")
        print(f"[*] 线程数: {self.config.threads}\n")

        with tqdm(total=len(self.config.ports), desc="扫描进度", unit="个") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                future_map = {executor.submit(self._scan_port, port): port for port in self.config.ports}
                for future in concurrent.futures.as_completed(future_map):
                    result = future.result()
                    self.results.append(result)
                    if result.is_open:
                        tqdm.write(f"[+] {result}")
                    pbar.update(1)

        self.results.sort(key=lambda r: r.port)
        return self.results

    def print_summary(self) -> None:
        """打印摘要"""
        open_ports = [r for r in self.results if r.is_open]
        print(f"\n{'=' * 50}")
        print(f"[+] 扫描完成！开放端口: {len(open_ports)}/{len(self.results)}")
        print("=" * 50)
        for result in open_ports:
            print(f"  {result}")

    def save_results(self) -> None:
        """保存结果"""
        if not self.config.output_file:
            return
        try:
            open_ports = [r for r in self.results if r.is_open]
            with open(self.config.output_file, "w", encoding="utf-8") as f:
                for result in open_ports:
                    f.write(f"{result.port}\n")
            print(f"\n[+] 结果已保存到: {self.config.output_file}")
        except OSError as e:
            print(f"\n[!] 保存失败: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="端口扫描器 - 扫描目标主机开放TCP端口")
    parser.add_argument("-H", "--host", required=True, help="目标主机IP或域名")
    parser.add_argument("-p", "--ports", default=",".join(str(p) for p in COMMON_PORTS),
                        help="端口范围，如 1-1000 或 80,443,8080")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help=f"线程数（默认{DEFAULT_THREADS}）")
    parser.add_argument("-o", "--output", help="输出文件")

    args = parser.parse_args()

    config = PortScannerConfig(
        host=args.host,
        ports=PortScanner.parse_ports(args.ports),
        threads=args.threads,
        output_file=args.output,
    )

    print("=" * 50)
    print("端口扫描器")
    print("=" * 50)

    scanner = PortScanner(config)
    scanner.scan()
    scanner.print_summary()
    scanner.save_results()


if __name__ == "__main__":
    main()
