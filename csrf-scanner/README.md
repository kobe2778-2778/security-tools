# CSRF漏洞扫描器

一款自动化CSRF（跨站请求伪造）漏洞检测工具，通过分析表单结构、CSRF Token、HTTP头安全配置，检测Web应用是否存在CSRF漏洞。

## ✨ 功能特点

- ✅ **自动表单检测** - 解析页面中所有表单，识别敏感操作
- ✅ **CSRF Token检查** - 检测表单是否包含有效的CSRF防护Token
- ✅ **HTTP头分析** - 检查Referer、Origin验证和Cookie SameSite属性
- ✅ **敏感操作识别** - 自动识别登录、修改、删除等敏感操作
- ✅ **POC生成** - 自动生成CSRF漏洞验证的HTML代码
- ✅ **结果保存** - 支持将发现的漏洞导出到文件

## 📦 安装

```bash
pip install -r requirements.txt