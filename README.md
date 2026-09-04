# Cobalt Strike Beacon 流量分析工具

当前版本：`v1.0.0`

用于在获得授权的应急响应、取证分析或实验环境中，读取 Cobalt Strike 的
`beacon_keys`，解密 HTTP Beacon 的元数据和 C2 数据，并直接在终端输出分析结果。

## 功能

- 从 Java 序列化的 `cobaltstrike.beacon_keys` 中提取 RSA 私钥
- 使用 Beacon 元数据恢复 AES-128 和 HMAC-SHA256 会话密钥
- 读取 `.pcap` 或 `.pcapng` 文件
- 自动重组 TCP 分片和重传数据
- 自动解析 HTTP 请求和响应
- 自动识别 Beacon 元数据和加密数据帧
- 解密客户端回传和服务端下发数据
- 解析 C2 地址、被控端 IP、主机名、用户名、上线程序名、时间、数据类型和内容
- 默认直接打印报告，也可以同时保存文本报告
- 提供深色科技风桌面 GUI，分析过程在后台线程执行
- GitHub Actions 自动执行语法检查并构建 Windows 程序

## 环境

需要 Python 3.10 或更高版本，以及以下依赖：

```powershell
python -m pip install scapy pycryptodome javaobj-py3
```

## 文件说明

```text
cobaltstrike.beacon_keys   RSA 密钥对文件
CS远程流量.pcapng           待分析的 PCAPNG 文件
cs_traffic_report.py        PCAP 流量分析和报告工具
extract_private_key.py      私钥提取工具
extract_session_keys.py     AES/HMAC 会话密钥提取工具
cs_traffic_gui.py           桌面 GUI 工具
requirements.txt            Python 依赖
.github/workflows/ci.yml    自动检查和 Windows 构建流程
```

`cobaltstrike.beacon_keys` 必须与抓包中的 Beacon 属于同一个 Team Server，
否则无法解开 RSA 元数据，也无法恢复 AES/HMAC 会话密钥。

## 直接分析 PCAP

默认会直接在终端输出报告：

```powershell
python cs_traffic_report.py "CS远程流量.pcapng"
```

指定密钥文件：

```powershell
python cs_traffic_report.py "CS远程流量.pcapng" `
  --beacon-keys "cobaltstrike.beacon_keys"
```

直接输出并保存报告：

```powershell
python cs_traffic_report.py "CS远程流量.pcapng" `
  --beacon-keys "cobaltstrike.beacon_keys" `
  --output "cs_traffic_report.txt"
```

报告示例：

```text
C2机器：192.168.8.129:80
被控机器：192.168.8.132 | DESKTOP-MBQHLNM | artifact_x64.exe
用户名：Lab

2026-09-04 13:45:49+08:00 | 192.168.8.132:49978 -> 192.168.8.129:80
方向：回传
类型：32 | Counter：2 | 长度：69
内容：ERROR kuhl_m_sekurlsa_acquireLSA...
HEX：000000020000004500000020...
```

其中：

- `传入` 表示从 C2 服务端发送到被控端的数据
- `回传` 表示从被控端发送到 C2 服务端的数据
- `类型`、`Counter` 和 `长度` 来自解密后的 Beacon 数据头
- `HEX` 保留完整明文，便于进一步分析二进制内容

## 提取 RSA 私钥

只提取私钥并打印到终端：

```powershell
python extract_private_key.py "cobaltstrike.beacon_keys"
```

保存为 PKCS#8 PEM 文件：

```powershell
python extract_private_key.py "cobaltstrike.beacon_keys" `
  --output "private_key.pem"
```

该 PEM 文件包含高敏感度 RSA 私钥。分析完成后应限制文件访问权限，或及时删除。

## 启动 GUI

```powershell
python cs_traffic_gui.py
```

在界面中选择 PCAP/PCAPNG 和 `cobaltstrike.beacon_keys`，点击 `ANALYZE` 后，
报告会直接显示在窗口中。可选填写报告文件路径，同时保存文本报告。

也可以构建 Windows 单文件程序：

```powershell
python -m pip install -r requirements.txt pyinstaller
pyinstaller --noconfirm --clean --onefile --windowed `
  --name CS-Traffic-Analyzer cs_traffic_gui.py
```

构建结果位于 `dist/CS-Traffic-Analyzer.exe`。

## 自动构建

`.github/workflows/ci.yml` 会在推送和 Pull Request 时：

- 安装项目依赖
- 执行 Python 语法检查
- 执行 Tkinter 可用性检查
- 在 Windows runner 上构建单文件 GUI 程序
- 将 EXE 作为 Actions Artifact 保存

工作流不会打包仓库中的密钥文件或 PCAP 文件。

## 提取 AES 和 HMAC Key

如果已经从 HTTP 请求的 `Cookie` 中提取出 Base64 元数据，可以保存到文本文件，
例如 `metadata.txt`，文件内容只放 Cookie 值本身，不要包含 `Cookie:` 前缀。

```powershell
python extract_session_keys.py "metadata.txt" `
  --key "cobaltstrike.beacon_keys"
```

也可以使用 PEM 私钥：

```powershell
python extract_session_keys.py "metadata.txt" `
  --key "private_key.pem"
```

脚本会执行以下流程：

```text
Base64 元数据
    -> RSA PKCS#1 v1.5 解密
    -> 校验 00 00 BE EF
    -> 提取 16 字节随机材料
    -> SHA-256
    -> AES Key = digest[:16]
    -> HMAC Key = digest[16:]
```

也支持从标准输入读取元数据：

```powershell
Get-Content "metadata.txt" | `
  python extract_session_keys.py - --key "cobaltstrike.beacon_keys"
```

## 常见问题

### 没有发现可解密数据

确认以下项目：

- 密钥文件是否来自生成该 Beacon 的 Team Server
- 抓包是否包含 Beacon 首次上线的元数据请求
- HTTP Cookie 是否完整，是否发生 TCP 分片丢失
- 抓包是否为 HTTP Beacon，而不是未解密的 HTTPS Beacon
- 运行命令时指定的 PCAP 和密钥路径是否正确

### 中文显示异常

工具会尝试 UTF-8、UTF-16LE 和 GB18030。PowerShell 终端仍可能受本地编码设置影响，
可以先执行：

```powershell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
```

### 数据量很大时运行较慢

建议先使用 Wireshark 或 `tshark` 按 C2 IP、端口和 TCP 流过滤，再对过滤后的 PCAP
进行分析。

## 安全说明

这些工具只能用于已获授权的网络流量、恶意样本取证和实验环境。`beacon_keys`、
导出的 PEM 私钥、会话密钥和解密后的 Beacon 数据都应按照敏感取证材料进行保护。
