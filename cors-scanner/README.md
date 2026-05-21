# CORS漏洞扫描器

一款自动化CORS（跨域资源共享）漏洞检测工具，检测Web应用的跨域配置是否存在安全漏洞，可能导致用户敏感信息泄露。

## ✨ 功能特点

- ✅ **多Origin测试** - 测试null、恶意域名、子域名欺骗等多种Origin
- ✅ **Credentials检测** - 检测是否允许携带凭据的跨域请求
- ✅ **通配符检测** - 检测ACAO为*且同时启用Credentials的危险配置
- ✅ **预检请求** - 支持OPTIONS预检请求分析
- ✅ **POC生成** - 自动生成漏洞利用验证代码
- ✅ **结果保存** - 支持将发现的漏洞导出到文件

## 📦 安装

```bash
pip install -r requirements.txt