# Fast Port Scanner

一个基于 Python 的多线程 TCP 端口扫描器。

## 功能

- 多线程扫描
- Banner Grabbing
- 彩色输出
- 自定义端口范围
- 保存结果
- 超时控制

## 技术栈

- Python
- socket
- threading
- argparse
- colorama
- tqdm

## 安装

```bash
pip install -r requirements.txt
```

## 使用方法

扫描默认端口：

```bash
python main.py scanme.nmap.org
```

指定端口范围：

```bash
python main.py 127.0.0.1 -s 1 -e 5000
```

设置超时：

```bash
python main.py 127.0.0.1 -t 0.5
```

## 示例输出

```text
[OPEN] Port 22 | OpenSSH
[OPEN] Port 80 | Apache
```

## 项目结构

```text
fast-port-scanner/
├── main.py
├── scanner.py
├── requirements.txt
├── README.md
└── .gitignore
```

## 注意

请仅对：

- 自己的设备
- 授权目标
- 测试环境

进行扫描。"# fast-port-scanner"  
"# fast-port-scanner"  
"# fast-port-scanner"  
"# fast-port-scanner"  
