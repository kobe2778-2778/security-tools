#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQL注入漏洞扫描器
支持报错注入检测和时间盲注检测
"""

import argparse
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests
from tqdm import tqdm

import payloads

# ============================================================
# 配置常量
# ============================================================

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

REQUEST_TIMEOUT = 15
DEFAULT_TIME_THRESHOLD = 5
SUPPORTED_DATABASES = ["MySQL", "PostgreSQL", "Oracle", "SQL Server", "SQLite"]

# ============================================================
# 数据结构
# ============================================================

@dataclass
class InjectionResult:
    """SQL注入检测结果"""
    url: str
    param: str
    payload: str
    injection_type: str  # "报错注入" 或 "时间盲注"
    detail: str
    status_code: int
    response_time: float = 0.0

    def __str__(self) -> str:
        lines = [
            f"类型: {self.injection_type}",
            f"URL: {self.url}",
            f"参数: {self.param}",
            f"载荷: {self.payload}",
            f"详情: {self.detail}",
            f"HTTP状态码: {self.status_code}",
        ]
        if self.response_time > 0:
            lines.append(f"响应时间: {self.response_time:.2f}秒")
        return "\n".join(lines)


@dataclass
class ScannerConfig:
    """扫描器配置"""
    url: str
    time_threshold: int = DEFAULT_TIME_THRESHOLD
    skip_error: bool = False
    skip_time: bool = False
    output_file: Optional[str] = None


# ============================================================
# 工具函数
# ============================================================

def setup_logging(verbose: bool = False) -> None:
    """配置日志"""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def disable_ssl_warnings() -> None:
    """禁用SSL警告"""
    requests.packages.urllib3.disable_warnings()


def normalize_url(url: str) -> str:
    """规范化URL，确保以/结尾"""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if not url.endswith("/"):
        url += "/"
    return url


def extract_params(url: str) -> dict:
    """从URL中提取GET参数，返回 {参数名: 参数值}"""
    parsed = urlparse(url)
    return {k: v[0] for k, v in parse_qs(parsed.query)}


def inject_param(url: str, param_name: str, payload: str) -> str:
    """将载荷注入到指定参数中，返回新URL"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param_name] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def safe_request(url: str, timeout: int = REQUEST_TIMEOUT) -> Optional[requests.Response]:
    """安全发送HTTP GET请求，异常时返回None"""
    try:
        return requests.get(
            url,
            headers=DEFAULT_HEADERS,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
    except requests.exceptions.RequestException as e:
        logging.debug(f"请求失败 {url}: {e}")
        return None


def load_payloads(file_path: str, fallback_func) -> list:
    """加载载荷，文件不存在时使用内置备份"""
    result = payloads.load_payloads_from_file(file_path)
    if not result:
        logging.warning(f"载荷文件不存在，使用内置载荷: {file_path}")
        result = fallback_func()
    return result


# ============================================================
# 错误特征匹配
# ============================================================

ERROR_PATTERNS = {
    "MySQL": [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"You have an error in your SQL syntax",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_.*",
        r"valid PostgreSQL result",
    ],
    "Oracle": [
        r"ORA-[0-9]{5}",
        r"Oracle error",
        r"Oracle.*Driver",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_.*",
        r"valid SQLite result",
    ],
    "SQL Server": [
        r"SQL Server.*Driver",
        r"Driver.*SQL Server",
        r"SQLServer JDBC Driver",
        r"com\.microsoft\.sqlserver",
        r"Unclosed quotation mark after the character string",
        r"Microsoft OLE DB Provider for ODBC Drivers",
        r"Microsoft OLE DB Provider for SQL Server",
        r"Incorrect syntax near",
    ],
    "通用": [
        r"Syntax error in string in query expression",
        r"Unclosed quotation mark",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        r"division by zero",
        r"Unknown column",
        r"Table.*doesn't exist",
        r"Column.*not found",
        r"Column count.*doesn't match",
    ],
}


def match_error_pattern(response_text: str) -> Optional[str]:
    """匹配响应中的SQL错误特征，返回数据库类型"""
    for db_type, patterns in ERROR_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return db_type
    return None


# ============================================================
# 扫描逻辑
# ============================================================

class SQLInjectionScanner:
    """SQL注入扫描器"""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.results: list[InjectionResult] = []

    def scan(self) -> list[InjectionResult]:
        """执行扫描，返回结果列表"""
        url = normalize_url(self.config.url)
        params = extract_params(url)

        if not params:
            print("[!] URL中没有GET参数，无法进行SQL注入测试")
            return []

        print(f"[*] 检测到 {len(params)} 个参数: {list(params.keys())}")
        print(f"[*] 时间盲注阈值: {self.config.time_threshold}秒\n")

        if not self.config.skip_error:
            self._scan_error_based(url, params)

        if not self.config.skip_time:
            self._scan_time_based(url, params)

        return self.results

    def _scan_error_based(self, url: str, params: dict) -> None:
        """报错注入检测"""
        print("[*] 开始报错注入检测...")

        error_payloads = load_payloads(
            "payloads/error_based.txt",
            payloads.get_default_error_payloads,
        )

        total = len(params) * len(error_payloads)

        with tqdm(total=total, desc="报错注入进度", unit="次") as pbar:
            for param_name in params:
                for payload in error_payloads:
                    test_url = inject_param(url, param_name, payload)
                    response = safe_request(test_url)

                    if response is None:
                        pbar.update(1)
                        continue

                    db_type = match_error_pattern(response.text)
                    if db_type:
                        result = InjectionResult(
                            url=test_url,
                            param=param_name,
                            payload=payload,
                            injection_type="报错注入",
                            detail=f"数据库类型: {db_type}",
                            status_code=response.status_code,
                        )
                        self.results.append(result)
                        tqdm.write(f"\n[+] 发现SQL注入漏洞: {test_url}")
                        tqdm.write(f"    参数: {param_name}, 载荷: {payload}")
                        tqdm.write(f"    数据库: {db_type}")

                    pbar.update(1)

        if not self.results:
            print("[-] 未发现报错注入漏洞")

    def _scan_time_based(self, url: str, params: dict) -> None:
        """时间盲注检测"""
        print("\n[*] 开始时间盲注检测...")

        time_payloads = load_payloads(
            "payloads/time_based.txt",
            payloads.get_default_time_payloads,
        )

        total = len(params) * len(time_payloads)

        with tqdm(total=total, desc="时间盲注进度", unit="次") as pbar:
            for param_name in params:
                for payload in time_payloads:
                    test_url = inject_param(url, param_name, payload)

                    start_time = time.time()
                    response = safe_request(test_url, timeout=self.config.time_threshold + 5)
                    elapsed = time.time() - start_time

                    if response is None:
                        pbar.update(1)
                        continue

                    if elapsed >= self.config.time_threshold:
                        result = InjectionResult(
                            url=test_url,
                            param=param_name,
                            payload=payload,
                            injection_type="时间盲注",
                            detail=f"响应时间异常",
                            status_code=response.status_code,
                            response_time=elapsed,
                        )
                        self.results.append(result)
                        tqdm.write(f"\n[+] 发现时间盲注漏洞: {test_url}")
                        tqdm.write(f"    参数: {param_name}, 载荷: {payload}")
                        tqdm.write(f"    响应时间: {elapsed:.2f}秒")

                    pbar.update(1)

        if not self.results:
            print("[-] 未发现时间盲注漏洞")


# ============================================================
# 输出
# ============================================================

def print_results(results: list[InjectionResult]) -> None:
    """打印扫描结果"""
    print(f"\n{'=' * 50}")
    print(f"[+] 扫描完成！共发现 {len(results)} 个SQL注入漏洞")
    print("=" * 50)

    if not results:
        return

    for i, result in enumerate(results, 1):
        print(f"\n--- 漏洞 {i} ---")
        print(result)


def save_results(results: list[InjectionResult], file_path: str) -> None:
    """保存结果到文件"""
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            for result in results:
                f.write(f"[{result.injection_type}] {result.url}\n")
                f.write(f"  参数: {result.param}\n")
                f.write(f"  载荷: {result.payload}\n")
                f.write(f"  详情: {result.detail}\n\n")
        print(f"\n[+] 结果已保存到: {file_path}")
    except OSError as e:
        print(f"\n[!] 保存结果失败: {e}")


# ============================================================
# 入口
# ============================================================

def build_argument_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器"""
    parser = argparse.ArgumentParser(
        description="SQL注入漏洞扫描器 - 检测GET参数中的SQL注入漏洞",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python scanner.py -u "http://test.com/page.php?id=1"
  python scanner.py -u "http://test.com/page.php?id=1&name=admin"
  python scanner.py -u "http://test.com/page.php?id=1" --no-error
  python scanner.py -u "http://test.com/page.php?id=1" --no-time
  python scanner.py -u "http://test.com/page.php?id=1" --time-threshold 10
  python scanner.py -u "http://test.com/page.php?id=1" -o result.txt
        """,
    )

    parser.add_argument(
        "-u", "--url", required=True,
        help="目标URL（包含参数），例如 http://test.com/page.php?id=1",
    )
    parser.add_argument(
        "-o", "--output",
        help="结果输出文件路径",
    )
    parser.add_argument(
        "--no-error", action="store_true",
        help="跳过报错注入检测",
    )
    parser.add_argument(
        "--no-time", action="store_true",
        help="跳过时间盲注检测",
    )
    parser.add_argument(
        "--time-threshold", type=int, default=DEFAULT_TIME_THRESHOLD,
        help=f"时间盲注阈值（秒），默认{DEFAULT_TIME_THRESHOLD}秒",
    )

    return parser


def main() -> None:
    """主入口"""
    disable_ssl_warnings()
    setup_logging()

    parser = build_argument_parser()
    args = parser.parse_args()

    config = ScannerConfig(
        url=args.url,
        time_threshold=args.time_threshold,
        skip_error=args.no_error,
        skip_time=args.no_time,
        output_file=args.output,
    )

    print("=" * 50)
    print("SQL注入漏洞扫描器")
    print("=" * 50)
    print(f"[*] 目标URL: {args.url}")
    print(f"[*] 时间盲注阈值: {args.time_threshold}秒\n")

    scanner = SQLInjectionScanner(config)
    results = scanner.scan()

    print_results(results)

    if config.output_file and results:
        save_results(results, config.output_file)

    if not results:
        print("\n[*] 提示：如果目标确实存在SQL注入，可能需要调整载荷或使用更高级的测试方法")


if __name__ == "__main__":
    main()
