#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件上传漏洞扫描器
检测目标Web应用是否存在文件上传漏洞
"""

import requests
import argparse
import sys
import os
import re
import random
import string
from urllib.parse import urljoin, urlparse
from tqdm import tqdm

# 禁用SSL警告
requests.packages.urllib3.disable_warnings()

# ========== 配置 ==========
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

TIMEOUT = 10


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


def get_builtin_extensions():
    """
    内置危险后缀名列表
    """
    return [
        ".php", ".php3", ".php4", ".php5", ".phtml", ".pht", ".phar",
        ".asp", ".aspx", ".asa", ".cer",
        ".jsp", ".jspx",
        ".php.jpg", ".php.png", ".php.gif",
        ".php%00.jpg", ".php%00",
        ".php;.jpg", ".PhP", ".PHP",
    ]


def get_builtin_content_types():
    """
    内置Content-Type列表
    """
    return [
        "application/x-php",
        "application/x-httpd-php",
        "image/jpeg",
        "image/png",
        "image/gif",
        "text/plain",
        "text/html",
        "application/octet-stream",
    ]


def generate_random_string(length=6):
    """
    生成随机字符串
    """
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def generate_webshell_content(extension, rand_str):
    """
    生成一个无害的测试文件内容
    上传成功后会在页面输出随机字符串，用来验证是否成功上传并执行
    """
    ext = extension.lower().split('.')[-1].replace('%00', '')
    
    if ext in ['php', 'php3', 'php4', 'php5', 'phtml', 'pht', 'phar']:
        return f"<?php echo '{rand_str}'; ?>"
    elif ext in ['asp', 'aspx']:
        return f"<% Response.Write(\"{rand_str}\") %>"
    elif ext in ['jsp', 'jspx']:
        return f"<% out.print(\"{rand_str}\"); %>"
    else:
        return f"<?php echo '{rand_str}'; ?>"


def detect_upload_form(url):
    """
    检测页面中是否存在文件上传表单
    返回: (上传URL, file参数名, 其他表单字段)
    """
    try:
        response = requests.get(
            url,
            headers=DEFAULT_HEADERS,
            timeout=TIMEOUT,
            verify=False
        )
        
        # 查找form标签
        form_pattern = r'<form[^>]*?action=["\']([^"\']*)["\'][^>]*?>(.*?)</form>'
        forms = re.findall(form_pattern, response.text, re.IGNORECASE | re.DOTALL)
        
        upload_forms = []
        for action, form_content in forms:
            # 查找 file 类型的 input
            file_pattern = r'<input[^>]*?type=["\']file["\'][^>]*?name=["\']([^"\']*)["\']'
            file_inputs = re.findall(file_pattern, form_content, re.IGNORECASE)
            
            if file_inputs:
                # 拼接完整上传URL
                upload_url = urljoin(url, action) if action else url
                upload_forms.append({
                    'upload_url': upload_url,
                    'file_param': file_inputs[0],
                })
        
        return upload_forms
    except Exception as e:
        print(f"[!] 检测上传表单失败: {e}")
        return []


def test_file_upload(target_url, upload_url, file_param, extension, content_type, rand_str):
    """
    测试单个文件上传
    返回: (成功标志, 上传详情, 访问URL)
    """
    filename = f"test_{rand_str}{extension}"
    file_content = generate_webshell_content(extension, rand_str)
    
    files = {
        file_param: (filename, file_content, content_type)
    }
    
    try:
        # 发送上传请求
        response = requests.post(
            upload_url,
            files=files,
            headers=DEFAULT_HEADERS,
            timeout=TIMEOUT,
            verify=False
        )
        
        # 尝试从响应中提取上传后的文件路径
        uploaded_path = extract_uploaded_path(response.text, filename)
        
        if uploaded_path:
            # 尝试访问上传的文件
            access_url = urljoin(target_url, uploaded_path)
            try:
                access_response = requests.get(
                    access_url,
                    headers=DEFAULT_HEADERS,
                    timeout=TIMEOUT,
                    verify=False
                )
                
                # 检查是否成功执行（响应中包含随机字符串）
                if rand_str in access_response.text:
                    return True, {
                        'upload_url': upload_url,
                        'filename': filename,
                        'extension': extension,
                        'content_type': content_type,
                        'access_url': access_url,
                        'upload_status': response.status_code,
                        'access_status': access_response.status_code,
                    }, access_url
            except:
                pass
        
        # 如果响应中没有明确路径，尝试常见路径
        common_paths = [
            f"uploads/{filename}",
            f"upload/{filename}",
            f"files/{filename}",
            f"images/{filename}",
            f"temp/{filename}",
            f"media/{filename}",
            f"{filename}",
        ]
        
        for path in common_paths:
            access_url = urljoin(target_url, path)
            try:
                access_response = requests.get(
                    access_url,
                    headers=DEFAULT_HEADERS,
                    timeout=TIMEOUT,
                    verify=False
                )
                if rand_str in access_response.text:
                    return True, {
                        'upload_url': upload_url,
                        'filename': filename,
                        'extension': extension,
                        'content_type': content_type,
                        'access_url': access_url,
                        'upload_status': response.status_code,
                        'access_status': access_response.status_code,
                    }, access_url
            except:
                continue
        
        return False, None, None
        
    except Exception as e:
        return False, None, None


def extract_uploaded_path(response_text, filename):
    """
    从响应中提取上传后的文件路径
    """
    # 常见的路径模式
    patterns = [
        rf'(?:src|href|path|file|url)=["\']([^"\']*{re.escape(filename)}[^"\']*)["\']',
        rf'(["\'][^"\']*{re.escape(filename)}[^"\']*["\'])',
        rf'(?:location|path|uploaded)[:\s]+["\']([^"\']*{re.escape(filename)}[^"\']*)["\']',
        rf'(?:/[\w/-]*{re.escape(filename)})',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, response_text, re.IGNORECASE)
        if match:
            path = match.group(1) if match.lastindex else match.group(0)
            # 清理引号
            path = path.strip('"\'')
            return path
    
    return None


def scan_upload_vulnerability(url, upload_url=None, file_param="file", threads=5):
    """
    主扫描函数
    """
    print("[*] 加载测试载荷...")
    
    # 加载后缀名
    extensions = load_payloads("payloads/extensions.txt")
    if not extensions:
        extensions = get_builtin_extensions()
    
    # 加载Content-Type
    content_types = load_payloads("payloads/content_types.txt")
    if not content_types:
        content_types = get_builtin_content_types()
    
    print(f"[*] 已加载 {len(extensions)} 个后缀名")
    print(f"[*] 已加载 {len(content_types)} 个Content-Type")
    
    # 如果没有指定上传URL，自动检测
    if not upload_url:
        print(f"[*] 正在检测页面中的上传表单...")
        forms = detect_upload_form(url)
        
        if forms:
            print(f"[+] 检测到 {len(forms)} 个上传表单:")
            for i, form in enumerate(forms):
                print(f"    {i+1}. 上传URL: {form['upload_url']}")
                print(f"       文件参数: {form['file_param']}")
            
            # 使用第一个表单
            upload_url = forms[0]['upload_url']
            file_param = forms[0]['file_param']
        else:
            if not upload_url:
                print("[!] 未检测到上传表单，请手动指定上传URL")
                print("[*] 使用示例: python scanner.py -u http://test.com -U http://test.com/upload.php")
                return None
    
    print(f"\n[*] 目标URL: {url}")
    print(f"[*] 上传URL: {upload_url}")
    print(f"[*] 文件参数: {file_param}")
    
    total_tests = len(extensions) * len(content_types)
    print(f"[*] 总测试组合: {total_tests}")
    print(f"[*] 开始文件上传漏洞扫描...\n")
    
    results = []
    
    with tqdm(total=total_tests, desc="扫描进度", unit="test") as pbar:
        for ext in extensions:
            for ct in content_types:
                rand_str = generate_random_string()
                
                success, detail, access_url = test_file_upload(
                    url, upload_url, file_param, ext, ct, rand_str
                )
                
                if success:
                    results.append(detail)
                    tqdm.write(f"\n[+] 发现文件上传漏洞!")
                    tqdm.write(f"    文件名: {detail['filename']}")
                    tqdm.write(f"    后缀名: {detail['extension']}")
                    tqdm.write(f"    Content-Type: {detail['content_type']}")
                    tqdm.write(f"    文件地址: {detail['access_url']}")
                    tqdm.write(f"    上传状态码: {detail['upload_status']}")
                    tqdm.write(f"    访问状态码: {detail['access_status']}")
                
                pbar.update(1)
    
    return results


def main():
    """
    命令行入口
    """
    parser = argparse.ArgumentParser(
        description="文件上传漏洞扫描器 - 检测文件上传点是否存在危险后缀名上传漏洞",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python scanner.py -u "http://test.com/upload.php"
  python scanner.py -u "http://test.com" -U "http://test.com/upload.php"
  python scanner.py -u "http://test.com/upload.php" -p "uploaded_file"
  python scanner.py -u "http://test.com/upload.php" -o result.txt
        """
    )
    
    parser.add_argument("-u", "--url", required=True,
                        help="目标URL")
    parser.add_argument("-U", "--upload-url",
                        help="上传接口URL（如不指定则自动检测）")
    parser.add_argument("-p", "--param", default="file",
                        help="文件参数名（默认: file）")
    parser.add_argument("-o", "--output",
                        help="结果输出文件路径")
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("文件上传漏洞扫描器")
    print("=" * 50)
    
    # 执行扫描
    results = scan_upload_vulnerability(
        url=args.url,
        upload_url=args.upload_url,
        file_param=args.param
    )
    
    # 输出结果
    print("\n" + "=" * 50)
    if results:
        print(f"[+] 扫描完成！共发现 {len(results)} 个可上传的后缀名")
        print("=" * 50)
        
        for i, result in enumerate(results, 1):
            print(f"\n--- 可上传后缀 {i} ---")
            print(f"文件名: {result['filename']}")
            print(f"后缀名: {result['extension']}")
            print(f"Content-Type: {result['content_type']}")
            print(f"文件地址: {result['access_url']}")
            print(f"上传状态码: {result['upload_status']}")
            print(f"访问状态码: {result['access_status']}")
    else:
        print("[-] 未发现文件上传漏洞")
        print("=" * 50)
    
    # 保存结果
    if args.output and results:
        with open(args.output, 'w', encoding='utf-8') as f:
            for result in results:
                f.write(f"文件名: {result['filename']}\n")
                f.write(f"后缀名: {result['extension']}\n")
                f.write(f"Content-Type: {result['content_type']}\n")
                f.write(f"文件地址: {result['access_url']}\n")
                f.write(f"上传状态码: {result['upload_status']}\n")
                f.write(f"访问状态码: {result['access_status']}\n\n")
        print(f"\n[+] 结果已保存到: {args.output}")
    
    if not results:
        print("\n[*] 提示：")
        print("    1. 可以手动指定上传URL: -U http://test.com/upload.php")
        print("    2. 目标可能对文件内容进行了检查，不仅限于后缀名")
        print("    3. 部分后缀如 .php.jpg 需要服务器配置解析漏洞才能利用")


if __name__ == "__main__":
    main()