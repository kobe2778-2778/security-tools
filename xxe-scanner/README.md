# XXE漏洞扫描器

一款自动化XXE（XML外部实体注入）漏洞检测工具，检测Web应用在解析XML时是否存在外部实体注入漏洞，可能导致任意文件读取、SSRF、命令执行。

## ✨ 功能特点

- ✅ **GET+POST双模式** - 同时检测GET参数和POST请求体中的XXE
- ✅ **多种载荷类型** - 基础文件读取、PHP封装器、XInclude、SOAP、SVG等
- ✅ **智能特征匹配** - 自动识别passwd、win.ini、命令输出等文件特征
- ✅ **多编码绕过** - 支持UTF-16编码绕过WAF
- ✅ **盲XXE检测** - 支持错误回显和时间延迟检测
- ✅ **实时进度条** - 使用 tqdm 显示测试进度
- ✅ **结果保存** - 支持将发现的漏洞导出到文件

## 📦 安装

```bash
pip install -r requirements.txt