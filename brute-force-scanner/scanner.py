#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
弱口令/暴力破解扫描器
检测Web应用登录接口是否存在弱口令或暴力破解漏洞
"""

import requests
import argparse
import sys
import re
import time
import random
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

requests.packages.urllib3.disable_warnings()

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

TIMEOUT = 10
THREADS = 10

COMMON_USERNAMES = [
    "admin", "administrator", "root", "test", "user",
    "guest", "manager", "webmaster", "system", "sa",
    "info", "support", "super", "master", "demo",
    "operator", "office", "service", "email", "mail",
    "postmaster", "webadmin", "sysadmin", "security",
]

COMMON_PASSWORDS = [
    "admin", "admin123", "admin123456", "123456", "12345678",
    "password", "passwd", "pass123", "p@ssw0rd", "p@ssword",
    "root", "root123", "toor", "test", "test123",
    "guest", "guest123", "demo", "demo123",
    "qwerty", "qwerty123", "1q2w3e4r", "abc123",
    "iloveyou", "monkey", "dragon", "master", "letmein",
    "123456789", "1234567890", "111111", "000000", "88888888",
    "password123", "password1", "Password", "PASSWORD",
    "Admin", "Admin123", "Root", "Root123",
    "", "null",
]

LOGIN_KEYWORDS = [
    "username", "user", "login", "email", "account",
    "name", "id", "uid", "uname", "usr",
    "password", "pass", "pwd", "passwd", "pin",
    "secret", "key", "code", "token",
]

SUCCESS_KEYWORDS = [
    "welcome", "dashboard", "logout", "sign out", "signout",
    "my account", "profile", "success", "successful",
    "登录成功", "欢迎", "退出", "注销",
]

FAILURE_KEYWORDS = [
    "incorrect", "invalid", "wrong", "error", "fail",
    "failed", "denied", "unauthorized", "forbidden",
    "not found", "does not exist", "try again",
    "密码错误", "用户名错误", "登录失败", "验证失败",
]

LOGIN_PATH_KEYWORDS = [
    "login", "signin", "sign-in", "logon", "auth",
    "authenticate", "admin", "administrator", "user",
    "account", "portal", "dashboard", "wp-login",
    "wp-admin", "cpanel", "phpmyadmin",
]


def load_wordlist(file_path):
    if not file_path:
        return None
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] 文件不存在: {file_path}")
        return None


def detect_login_forms(url):
    try:
        response = requests.get(
            url,
            headers=DEFAULT_HEADERS,
            timeout=TIMEOUT,
            verify=False
        )
        
        forms = []
        form_pattern = r'<form[^>]*?action=["\']([^"\']*)["\'][^>]*?method=["\']([^"\']*)["\'][^>]*?>(.*?)</form>'
        matches = re.findall(form_pattern, response.text, re.IGNORECASE | re.DOTALL)
        
        for action, method, form_content in matches:
            form_url = urljoin(url, action) if action else url
            
            input_pattern = r'<input[^>]*?name=["\']([^"\']*)["\'][^>]*?(?:type=["\']([^"\']*)["\'])?[^>]*?>'
            inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
            
            username_param = None
            password_param = None
            
            for input_name, input_type in inputs:
                name_lower = input_name.lower()
                type_lower = input_type.lower() if input_type else ""
                
                if type_lower == "password" and not password_param:
                    password_param = input_name
                
                for keyword in ["user", "login", "email", "account", "name"]:
                    if keyword in name_lower and not username_param:
                        username_param = input_name
                        break
                
                if type_lower == "email" and not username_param:
                    username_param = input_name
            
            if password_param:
                forms.append({
                    "url": form_url,
                    "method": method.upper(),
                    "username_param": username_param or "username",
                    "password_param": password_param,
                })
        
        return forms
        
    except Exception as e:
        print(f"[!] 获取页面失败: {e}")
        return []


def detect_login_paths(url):
    login_urls = []
    base_url = url.rstrip('/')
    
    for path in LOGIN_PATH_KEYWORDS:
        login_urls.append(f"{base_url}/{path}")
        login_urls.append(f"{base_url}/{path}.php")
        login_urls.append(f"{base_url}/{path}.asp")
        login_urls.append(f"{base_url}/{path}.aspx")
        login_urls.append(f"{base_url}/{path}.jsp")
    
    print(f"[*] 探测 {len(LOGIN_PATH_KEYWORDS)} 个常见登录路径...")
    
    found = []
    with tqdm(total=len(login_urls), desc="路径探测", unit="url") as pbar:
        for login_url in login_urls:
            try:
                response = requests.get(
                    login_url,
                    headers=DEFAULT_HEADERS,
                    timeout=5,
                    verify=False,
                    allow_redirects=False
                )
                
                if response.status_code == 200:
                    page_lower = response.text.lower()
                    has_login = any(kw in page_lower for kw in ["password", "login", "sign in", "登录"])
                    if has_login:
                        found.append(login_url)
                        tqdm.write(f"\n[+] 发现登录页面: {login_url}")
            except:
                pass
            pbar.update(1)
    
    return found


def try_login(login_url, method, username_param, password_param, username, password):
    try:
        data = {
            username_param: username,
            password_param: password,
        }
        
        headers = DEFAULT_HEADERS.copy()
        
        if method == "POST":
            response = requests.post(
                login_url,
                data=data,
                headers=headers,
                timeout=TIMEOUT,
                verify=False,
                allow_redirects=True
            )
        else:
            params = data
            response = requests.get(
                login_url,
                params=params,
                headers=headers,
                timeout=TIMEOUT,
                verify=False,
                allow_redirects=True
            )
        
        response_text = response.text.lower()
        response_url = response.url.lower()
        
        success_score = 0
        failure_score = 0
        
        for keyword in SUCCESS_KEYWORDS:
            if keyword.lower() in response_text or keyword.lower() in response_url:
                success_score += 1
        
        for keyword in FAILURE_KEYWORDS:
            if keyword.lower() in response_text:
                failure_score += 1
        
        if response.status_code in [301, 302]:
            redirect = response.headers.get("Location", "")
            if any(kw in redirect.lower() for kw in SUCCESS_KEYWORDS):
                success_score += 2
        
        has_redirected = response_url != login_url.lower()
        if has_redirected and "login" not in response_url:
            success_score += 2
        
        if success_score > failure_score and success_score >= 2:
            return True, response
        elif failure_score > 0:
            return False, response
        elif has_redirected and success_score >= 1:
            return True, response
        else:
            return False, response
            
    except Exception:
        return None, None


def brute_force_login(url, form_info, usernames, passwords):
    login_url = form_info["url"]
    method = form_info["method"]
    username_param = form_info["username_param"]
    password_param = form_info["password_param"]
    
    results = []
    attempts = []
    
    for username in usernames:
        for password in passwords:
            attempts.append((username, password))
    
    total_attempts = len(attempts)
    
    print(f"\n[*] 开始暴力破解...")
    print(f"[*] 登录URL: {login_url}")
    print(f"[*] 方法: {method}")
    print(f"[*] 用户名参数: {username_param}")
    print(f"[*] 密码参数: {password_param}")
    print(f"[*] 用户名数: {len(usernames)}")
    print(f"[*] 密码数: {len(passwords)}")
    print(f"[*] 总尝试次数: {total_attempts}")
    
    found_count = 0
    blocked = False
    last_request_time = 0
    
    with tqdm(total=total_attempts, desc="爆破进度", unit="次") as pbar:
        for username, password in attempts:
            if blocked:
                break
            
            elapsed = time.time() - last_request_time
            if elapsed < 0.1:
                time.sleep(0.1 - elapsed)
            
            success, response = try_login(
                login_url, method, username_param, password_param,
                username, password
            )
            last_request_time = time.time()
            
            if success is None:
                pass
            elif success:
                found_count += 1
                result = {
                    "username": username,
                    "password": password,
                    "login_url": login_url,
                    "status_code": response.status_code if response else 0,
                    "final_url": response.url if response else "",
                    "response_length": len(response.text) if response else 0,
                }
                results.append(result)
                
                tqdm.write(f"\n[+] 找到有效凭据!")
                tqdm.write(f"    用户名: {username}")
                tqdm.write(f"    密码: {password}")
                tqdm.write(f"    状态码: {result['status_code']}")
            elif response and response.status_code == 429:
                tqdm.write(f"\n[!] 检测到速率限制 (HTTP 429)，停止爆破")
                blocked = True
                break
            
            pbar.update(1)
            
            if found_count >= 5:
                tqdm.write(f"\n[!] 已找到 {found_count} 组凭据，停止爆破")
                break
    
    return results, blocked


def main():
    parser = argparse.ArgumentParser(
        description="弱口令/暴力破解扫描器 - 检测Web登录接口弱口令漏洞",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python scanner.py -u "http://test.com/login.php"
  python scanner.py -u "http://test.com" --auto-detect
  python scanner.py -u "http://test.com/login.php" -U admin,root -P admin,123456
  python scanner.py -u "http://test.com/login.php" --user-file users.txt --pass-file pass.txt
  python scanner.py -u "http://test.com/login.php" -o result.txt
        """
    )
    
    parser.add_argument("-u", "--url", required=True,
                        help="目标URL")
    parser.add_argument("-U", "--usernames",
                        help="用户名列表，逗号分隔")
    parser.add_argument("-P", "--passwords",
                        help="密码列表，逗号分隔")
    parser.add_argument("--user-file",
                        help="用户名字典文件路径")
    parser.add_argument("--pass-file",
                        help="密码字典文件路径")
    parser.add_argument("--auto-detect", action="store_true",
                        help="自动探测登录页面")
    parser.add_argument("-o", "--output",
                        help="结果输出文件路径")
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("弱口令/暴力破解扫描器")
    print("=" * 50)
    
    usernames = COMMON_USERNAMES
    passwords = COMMON_PASSWORDS
    
    if args.usernames:
        usernames = [u.strip() for u in args.usernames.split(',')]
    if args.passwords:
        passwords = [p.strip() for p in args.passwords.split(',')]
    if args.user_file:
        custom = load_wordlist(args.user_file)
        if custom:
            usernames = custom
    if args.pass_file:
        custom = load_wordlist(args.pass_file)
        if custom:
            passwords = custom
    
    login_forms = detect_login_forms(args.url)
    
    if not login_forms:
        print("\n[-] 未在页面中检测到登录表单")
        
        if args.auto_detect:
            print("[*] 开始自动探测登录路径...")
            login_urls = detect_login_paths(args.url)
            
            if not login_urls:
                print("[-] 未找到登录页面")
                sys.exit(1)
            
            print(f"\n[+] 找到 {len(login_urls)} 个登录页面")
            target_url = login_urls[0]
            print(f"[*] 使用: {target_url}")
            
            login_forms = detect_login_forms(target_url)
            if not login_forms:
                print("[-] 该页面仍无表单，尝试手动指定参数")
                login_forms = [{
                    "url": target_url,
                    "method": "POST",
                    "username_param": "username",
                    "password_param": "password",
                }]
        else:
            print("[*] 使用默认参数，登录接口为当前URL")
            login_forms = [{
                "url": args.url,
                "method": "POST",
                "username_param": "username",
                "password_param": "password",
            }]
    
    all_results = []
    
    for i, form in enumerate(login_forms):
        if i > 0:
            print(f"\n{'─' * 50}")
        
        results, blocked = brute_force_login(args.url, form, usernames, passwords)
        all_results.extend(results)
        
        if blocked:
            break
    
    print(f"\n{'=' * 50}")
    if all_results:
        print(f"[+] 扫描完成！找到 {len(all_results)} 组有效凭据")
        print("=" * 50)
        
        for i, result in enumerate(all_results, 1):
            print(f"\n凭据 {i}:")
            print(f"  用户名: {result['username']}")
            print(f"  密码: {result['password']}")
            print(f"  登录URL: {result['login_url']}")
            print(f"  状态码: {result['status_code']}")
    else:
        print("[-] 未找到有效凭据")
        print("=" * 50)
    
    if args.output and all_results:
        with open(args.output, 'w', encoding='utf-8') as f:
            for result in all_results:
                f.write(f"用户名: {result['username']}\n")
                f.write(f"密码: {result['password']}\n")
                f.write(f"登录URL: {result['login_url']}\n")
                f.write(f"状态码: {result['status_code']}\n\n")
        print(f"\n[+] 结果已保存到: {args.output}")
    
    if not all_results:
        print("\n[*] 提示：")
        print("    1. 可使用 --auto-detect 自动探测登录路径")
        print("    2. 自定义用户名/密码: -U user1,user2 -P pass1,pass2")
        print("    3. 使用字典文件: --user-file users.txt --pass-file pass.txt")
        print("    4. 目标可能有验证码或速率限制")


if __name__ == "__main__":
    main()