#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CSRF漏洞扫描器
检测Web应用中的表单和敏感操作是否存在CSRF（跨站请求伪造）漏洞
"""

import requests
import argparse
import sys
import re
import random
import string
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from tqdm import tqdm

requests.packages.urllib3.disable_warnings()

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

TIMEOUT = 10

CSRF_TOKEN_NAMES = [
    'csrf', 'csrf_token', 'csrftoken', 'csrf-token', 'xsrf', 'xsrf_token',
    '_csrf', '_token', 'token', 'authenticity_token', 'nonce',
    '__RequestVerificationToken', 'anticsrf', 'csrfmiddlewaretoken',
    'XSRF-TOKEN', 'X-CSRF-TOKEN', 'X-CSRFToken',
]


def extract_forms(url, html):
    """
    从HTML中提取所有表单
    """
    soup = BeautifulSoup(html, 'html.parser')
    forms = []
    
    for form in soup.find_all('form'):
        form_info = {
            'action': form.get('action', ''),
            'method': form.get('method', 'get').upper(),
            'id': form.get('id', ''),
            'inputs': []
        }
        
        for input_tag in form.find_all('input'):
            form_info['inputs'].append({
                'name': input_tag.get('name', ''),
                'type': input_tag.get('type', 'text'),
                'value': input_tag.get('value', ''),
            })
        
        forms.append(form_info)
    
    return forms


def has_csrf_token(form):
    """
    检查表单是否包含CSRF token
    """
    for input_field in form['inputs']:
        if input_field['type'] == 'hidden':
            name_lower = input_field['name'].lower()
            for token_name in CSRF_TOKEN_NAMES:
                if token_name.lower() in name_lower:
                    return True, input_field['name']
    
    return False, None


def check_sensitive_form(form):
    """
    判断表单是否是敏感操作
    """
    sensitive_keywords = [
        'login', 'register', 'password', 'email', 'profile', 'settings',
        'transfer', 'payment', 'checkout', 'order', 'delete', 'remove',
        'update', 'change', 'edit', 'admin', 'logout', 'account',
        'msg', 'message', 'comment', 'post', 'publish', 'submit',
        'add', 'create', 'save', 'config', 'role', 'permission',
    ]
    
    action_lower = form['action'].lower()
    form_id_lower = form['id'].lower()
    
    for keyword in sensitive_keywords:
        if keyword in action_lower or keyword in form_id_lower:
            return True, keyword
    
    for input_field in form['inputs']:
        name_lower = input_field['name'].lower()
        for keyword in sensitive_keywords:
            if keyword in name_lower:
                return True, keyword
    
    return False, None


def check_referer_header(url):
    """
    检查服务器是否验证Referer头
    """
    try:
        headers_without_referer = DEFAULT_HEADERS.copy()
        response1 = requests.post(
            url,
            headers=headers_without_referer,
            timeout=TIMEOUT,
            verify=False,
            allow_redirects=False
        )
        
        headers_with_fake_referer = DEFAULT_HEADERS.copy()
        headers_with_fake_referer['Referer'] = 'https://evil.com/fake.html'
        response2 = requests.post(
            url,
            headers=headers_with_fake_referer,
            timeout=TIMEOUT,
            verify=False,
            allow_redirects=False
        )
        
        if response1.status_code == response2.status_code and response1.status_code < 400:
            return True, "服务器未验证Referer头"
        
        return False, None
        
    except:
        return None, None


def check_origin_header(url):
    """
    检查服务器是否验证Origin头
    """
    try:
        headers_without_origin = DEFAULT_HEADERS.copy()
        response1 = requests.post(
            url,
            headers=headers_without_origin,
            timeout=TIMEOUT,
            verify=False,
            allow_redirects=False
        )
        
        headers_with_fake_origin = DEFAULT_HEADERS.copy()
        headers_with_fake_origin['Origin'] = 'https://evil.com'
        response2 = requests.post(
            url,
            headers=headers_with_fake_origin,
            timeout=TIMEOUT,
            verify=False,
            allow_redirects=False
        )
        
        if response1.status_code == response2.status_code and response1.status_code < 400:
            return True, "服务器未验证Origin头"
        
        return False, None
        
    except:
        return None, None


def check_samesite_cookie(response):
    """
    检查Cookie是否设置了SameSite属性
    """
    set_cookie_headers = response.headers.get('Set-Cookie', '')
    
    if not set_cookie_headers:
        return True, "未设置Cookie"
    
    if 'SameSite' not in set_cookie_headers:
        return True, "Cookie未设置SameSite属性"
    
    if 'SameSite=None' in set_cookie_headers and 'Secure' not in set_cookie_headers:
        return True, "SameSite=None但未设置Secure标志"
    
    return False, None


def check_csrf_vulnerability(url):
    """
    主检测函数
    """
    print(f"[*] 目标URL: {url}")
    print(f"[*] 正在获取页面内容...")
    
    try:
        response = requests.get(
            url,
            headers=DEFAULT_HEADERS,
            timeout=TIMEOUT,
            verify=False
        )
    except Exception as e:
        print(f"[!] 无法访问目标: {e}")
        return None
    
    print(f"[*] 响应状态码: {response.status_code}")
    print(f"[*] 页面大小: {len(response.text)} 字节")
    
    forms = extract_forms(url, response.text)
    print(f"\n[*] 检测到 {len(forms)} 个表单\n")
    
    if not forms:
        print("[-] 页面中没有检测到表单")
        return None
    
    results = []
    
    for i, form in enumerate(forms, 1):
        form_url = urljoin(url, form['action']) if form['action'] else url
        print(f"{'─' * 50}")
        print(f"表单 {i}:")
        print(f"  Action: {form_url}")
        print(f"  Method: {form['method']}")
        print(f"  Input字段数: {len(form['inputs'])}")
        
        has_token, token_name = has_csrf_token(form)
        is_sensitive, keyword = check_sensitive_form(form)
        
        issues = []
        
        if is_sensitive:
            print(f"  ⚠ 敏感操作 (匹配关键词: {keyword})")
            issues.append(f"敏感操作: {keyword}")
        
        if not has_token:
            print(f"  ❌ 未检测到CSRF Token")
            issues.append("缺少CSRF Token")
        else:
            print(f"  ✅ 检测到CSRF Token: {token_name}")
        
        if form['method'] == 'GET' and is_sensitive:
            print(f"  ❌ 敏感操作使用了GET方法")
            issues.append("敏感操作使用GET方法")
        
        if issues:
            result = {
                'form_index': i,
                'form_url': form_url,
                'method': form['method'],
                'issues': issues,
                'inputs': form['inputs'],
                'is_sensitive': is_sensitive,
                'has_csrf_token': has_token,
                'token_name': token_name if has_token else None,
            }
            results.append(result)
    
    print(f"\n{'─' * 50}")
    print(f"[*] 正在检查HTTP头安全配置...")
    
    referer_issue, referer_detail = check_referer_header(url)
    if referer_issue:
        print(f"  ❌ {referer_detail}")
        for result in results:
            result['issues'].append(referer_detail)
    
    origin_issue, origin_detail = check_origin_header(url)
    if origin_issue:
        print(f"  ❌ {origin_detail}")
        for result in results:
            result['issues'].append(origin_detail)
    
    cookie_issue, cookie_detail = check_samesite_cookie(response)
    if cookie_issue:
        print(f"  ❌ {cookie_detail}")
        for result in results:
            result['issues'].append(cookie_detail)
    
    if not cookie_issue and not origin_issue and not referer_issue:
        print(f"  ✅ HTTP头安全配置正常")
    
    return results


def generate_poc(result, target_url):
    """
    生成CSRF漏洞的POC（Proof of Concept）HTML代码
    """
    form_url = result['form_url']
    method = result['method']
    inputs = result['inputs']
    
    inputs_html = ""
    for inp in inputs:
        if inp['type'] != 'submit':
            input_type = inp['type'] if inp['type'] else 'text'
            inputs_html += f'    <input type="{input_type}" name="{inp["name"]}" value="{inp["value"]}">\n'
    
    poc = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF POC</title>
</head>
<body>
    <h2>CSRF漏洞验证 - 表单 {result['form_index']}</h2>
    <p>目标: {form_url}</p>
    <form action="{form_url}" method="{method}">
{inputs_html}    <input type="submit" value="点击触发">
    </form>
    <script>
        // 自动提交
        // document.forms[0].submit();
    </script>
</body>
</html>"""
    
    return poc


def main():
    parser = argparse.ArgumentParser(
        description="CSRF漏洞扫描器 - 检测Web应用中的CSRF漏洞",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python scanner.py -u "http://test.com/profile.php"
  python scanner.py -u "http://test.com/login.php" -o result.txt
  python scanner.py -u "http://test.com/admin.php" --poc
        """
    )
    
    parser.add_argument("-u", "--url", required=True,
                        help="目标URL")
    parser.add_argument("-o", "--output",
                        help="结果输出文件路径")
    parser.add_argument("--poc", action="store_true",
                        help="生成CSRF漏洞的POC HTML代码")
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("CSRF漏洞扫描器")
    print("=" * 50)
    
    results = check_csrf_vulnerability(args.url)
    
    print("\n" + "=" * 50)
    if results:
        print(f"[+] 扫描完成！发现 {len(results)} 个可能存在CSRF漏洞的表单")
        print("=" * 50)
        
        for i, result in enumerate(results, 1):
            print(f"\n--- 漏洞 {i} ---")
            print(f"表单位置: {result['form_url']}")
            print(f"请求方法: {result['method']}")
            print(f"是否敏感操作: {'是' if result['is_sensitive'] else '否'}")
            print(f"CSRF Token: {'有 (' + result['token_name'] + ')' if result['has_csrf_token'] else '无'}")
            print(f"发现的问题:")
            for issue in result['issues']:
                print(f"  - {issue}")
        
        if args.poc:
            print(f"\n{'=' * 50}")
            print("[*] 生成POC HTML代码:")
            print("=" * 50)
            for result in results:
                poc = generate_poc(result, args.url)
                print(f"\n--- 表单 {result['form_index']} 的POC ---")
                print(poc)
    else:
        print("[-] 未发现明显的CSRF漏洞")
        print("=" * 50)
    
    if args.output and results:
        with open(args.output, 'w', encoding='utf-8') as f:
            for result in results:
                f.write(f"表单 {result['form_index']}:\n")
                f.write(f"  URL: {result['form_url']}\n")
                f.write(f"  Method: {result['method']}\n")
                f.write(f"  问题: {', '.join(result['issues'])}\n\n")
        print(f"\n[+] 结果已保存到: {args.output}")


if __name__ == "__main__":
    main()