# Wirepeek

**窥探网线之中** — 高性能网络数据包分析器，配备现代化终端界面。如果说 [btop](https://github.com/aristocratos/btop) 之于 top，那么 Wirepeek 之于 tcpdump。

[![CI](https://github.com/lucientong/wirepeek/actions/workflows/ci.yml/badge.svg)](https://github.com/lucientong/wirepeek/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lucientong/wirepeek.svg)](https://github.com/lucientong/wirepeek/releases/latest)
[![Codecov](https://codecov.io/gh/lucientong/wirepeek/branch/master/graph/badge.svg)](https://codecov.io/gh/lucientong/wirepeek)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/lucientong/wirepeek)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](https://github.com/lucientong/wirepeek/blob/master/LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/lucientong/wirepeek)](https://hub.docker.com/r/lucientong/wirepeek)
[![GitHub Downloads](https://img.shields.io/github/downloads/lucientong/wirepeek/total)](https://github.com/lucientong/wirepeek/releases)

[English](README.md) · [架构文档](docs/zh/architecture.md) · [更新日志](CHANGELOG.md)

## 为什么选择 Wirepeek？

| 痛点 | 现有工具 | Wirepeek |
|------|---------|----------|
| **输出不可读** | tcpdump 显示原始十六进制和 TCP 标志 | 自动重组流，显示 `GET /api → 200 OK (43ms)` |
| **需要 GUI** | Wireshark 需要桌面环境 — SSH 下无法使用 | 现代 TUI (FTXUI)，支持终端、SSH、tmux、Docker |
| **仅基于端口过滤** | tcpdump 需要 `port 80` 来过滤 HTTP | 启发式协议检测 — 在任意端口识别 HTTP |
| **无延迟分析** | 需要外部脚本计算时延 | 内置 P50/P95/P99 延迟统计 (T-Digest)，实时图表 |
| **GC 导致丢包** | Go 实现的工具 (termshark) 高吞吐下丢包 | C++ 零拷贝解析，无锁队列，支持 10Gbps+ |

## 核心特性

- **自动协议检测** — HTTP/1.1、HTTP/2、gRPC、WebSocket、DNS、TLS、MySQL、Redis
- **请求/响应视图** — 看到 URL、方法、状态码、请求头、请求体 — 而非原始字节
- **内置延迟分析** — 请求→响应时间、TCP/TLS 握手时长、P50/P95/P99 百分位
- **现代终端界面** — 可滚动列表、详情面板、实时流量图表、交互式过滤器
- **零拷贝解析** — 直接在 mmap 环形缓冲区上指针操作，无逐包内存分配
- **多种导出格式** — pcap (Wireshark)、HAR (浏览器)、JSON (脚本/CI)
- **无头模式** — 类 tcpdump 输出，支持管道和脚本

## 安装

### Homebrew (macOS / Linux)

```bash
brew install lucientong/tap/wirepeek
```

### 静态二进制

从 [GitHub Releases](https://github.com/lucientong/wirepeek/releases/latest) 下载：

```bash
# Linux x86_64
curl -Lo wirepeek https://github.com/lucientong/wirepeek/releases/latest/download/wirepeek-linux-x86_64
chmod +x wirepeek && sudo mv wirepeek /usr/local/bin/

# Linux arm64
curl -Lo wirepeek https://github.com/lucientong/wirepeek/releases/latest/download/wirepeek-linux-arm64
chmod +x wirepeek && sudo mv wirepeek /usr/local/bin/

# macOS (通用二进制)
curl -Lo wirepeek https://github.com/lucientong/wirepeek/releases/latest/download/wirepeek-macos-universal
chmod +x wirepeek && sudo mv wirepeek /usr/local/bin/
```

### AUR (Arch Linux) - 待支持

```bash
yay -S wirepeek
```

### Debian / Ubuntu

```bash
curl -LO https://github.com/lucientong/wirepeek/releases/latest/download/wirepeek_amd64.deb
sudo dpkg -i wirepeek_amd64.deb
```

### 从源码构建

```bash
# 前置条件：CMake 3.20+，支持 C++20 的编译器，libpcap-dev
# Ubuntu/Debian:
sudo apt install build-essential cmake libpcap-dev

# macOS:
brew install cmake

# 构建
git clone https://github.com/lucientong/wirepeek.git
cd wirepeek
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# 安装
sudo cmake --install build
```

## 快速开始

```bash
# 在网络接口上抓包（需要 root/sudo）
sudo wirepeek -i eth0

# 使用 BPF 过滤表达式
sudo wirepeek -i eth0 -f "tcp port 80"

# 读取 pcap 文件
wirepeek --read capture.pcap

# 无头模式（类 tcpdump 输出）
sudo wirepeek --headless -i eth0 -c 100

# 按协议过滤
sudo wirepeek -i eth0 --protocol http

# 导出为 HAR 格式
sudo wirepeek -i eth0 --export har -o output.har
```

### 示例输出（无头模式）

```
14:32:01.482910  192.168.1.10:54312 -> 93.184.216.34:80 TCP [SYN] len=0
14:32:01.523847  93.184.216.34:80 -> 192.168.1.10:54312 TCP [SYN, ACK] len=0
14:32:01.523901  192.168.1.10:54312 -> 93.184.216.34:80 TCP [ACK] len=0
14:32:01.524102  192.168.1.10:54312 -> 93.184.216.34:80 TCP [PSH, ACK] len=73
14:32:01.565432  93.184.216.34:80 -> 192.168.1.10:54312 TCP [ACK] len=1256
```

## 架构

详见[架构文档](docs/zh/architecture.md)。

```
┌─────────────────────────────────────────────────────┐
│                    CLI / TUI                         │
├──────────┬──────────┬──────────┬────────────────────┤
│ 抓包引擎  │ 协议解析  │ 应用层协议 │     分析引擎       │
│ (libpcap)│ (L2-L4)  │ (L7)     │ (延迟/统计)        │
├──────────┴──────────┴──────────┴────────────────────┤
│              核心类型（零拷贝）                        │
└─────────────────────────────────────────────────────┘
```

## 开发进度

| 阶段 | 描述 | 状态 |
|------|------|------|
| 1 | 抓包引擎 + 基础协议解析 (Ethernet/IP/TCP/UDP) | ✅ 已完成 |
| 2 | TCP 流重组 | ✅ 已完成 |
| 3 | HTTP/1.1 解析 + 协议自动检测 | ✅ 已完成 |
| 4 | 终端界面 (FTXUI) | ✅ 已完成 |
| 5 | 延迟分析 + 流量统计 | ⬜ 计划中 |
| 6 | HTTP/2、gRPC、DNS、TLS、WebSocket | ⬜ 计划中 |
| 7 | 导出功能 (pcap/HAR/JSON) | ⬜ 计划中 |
| 8 | 界面完善 + 过滤器 + 图表 | ⬜ 计划中 |

## 贡献

欢迎贡献！请：

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 遵循 [Google C++ 代码规范](https://google.github.io/styleguide/cppguide.html)（C++20 扩展）
4. 确保所有测试通过 (`ctest --test-dir build`)
5. 提交 Pull Request

## 许可证

本项目基于 [Apache License 2.0](LICENSE) 许可。

Copyright 2026 lucientong
