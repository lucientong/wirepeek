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

[English](README.md) · [架构文档](docs/zh/architecture.md) · [基准测试](docs/en/benchmarks.md) · [更新日志](CHANGELOG.md)

## 为什么选择 Wirepeek？

| 痛点 | 现有工具 | Wirepeek |
|------|---------|----------|
| **输出不可读** | tcpdump 显示原始十六进制和 TCP 标志 | 自动重组流，显示 `GET /api → 200 OK (43ms)` |
| **需要 GUI** | Wireshark 需要桌面环境 — SSH 下无法使用 | 现代 TUI (FTXUI)，支持终端、SSH、tmux、Docker |
| **仅基于端口过滤** | tcpdump 需要 `port 80` 来过滤 HTTP | 启发式协议检测 — 在任意端口识别 HTTP |
| **无延迟分析** | 需要外部脚本计算时延 | 内置 P50/P95/P99（T-Digest）与端点聚合 |
| **可预测的数据包处理** | 托管运行时可能引入垃圾回收停顿 | C++ 解析，使用指向 libpcap 数据包缓冲区的零拷贝 span |

## 核心特性

- **应用层协议** — HTTP/1.1（chunked、pipelining、HEAD/204/304）、DNS、TLS 握手元数据（SNI/ALPN）、WebSocket、Redis RESP、最小 HTTP/2 / gRPC 帧解析
- **请求/响应视图** — 方法、URL、状态码、请求头、大小与基于抓包时间戳的延迟
- **被动 APM** — 归一化端点统计、TCP 握手 / TTFB / 传输时长、OpenMetrics 导出
- **现代终端界面** — 可滚动列表、详情面板、流量 sparkline、过滤、暂停/跟随、端点视图（`e`）
- **链路层支持** — Ethernet、BSD NULL/LOOP、Linux SLL/SLL2、Raw IP（适配 `lo0` / `-i any`）
- **零拷贝数据包解析** — 非持有型 span 指向 libpcap 回调缓冲区
- **多种导出格式** — pcap、HAR 1.2、NDJSON
- **无头模式** — 类 tcpdump 输出，支持管道和脚本

## 安装

### Homebrew (macOS / Linux)

```bash
brew install lucientong/tap/wirepeek
```

### 静态二进制

从 [GitHub Releases](https://github.com/lucientong/wirepeek/releases/latest) 下载：

```bash
curl -Lo wirepeek https://github.com/lucientong/wirepeek/releases/latest/download/wirepeek-linux-x86_64
chmod +x wirepeek && sudo mv wirepeek /usr/local/bin/
```

### 从源码构建

```bash
sudo apt install build-essential cmake libpcap-dev   # Ubuntu/Debian
brew install cmake                                   # macOS

git clone https://github.com/lucientong/wirepeek.git
cd wirepeek
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
sudo cmake --install build
```

可选构建：

```bash
cmake -B build-bench -DWIREPEEK_BUILD_BENCHMARKS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-bench -j$(nproc)

cmake -B build-fuzz -DWIREPEEK_BUILD_FUZZERS=ON -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang
cmake --build build-fuzz -j$(nproc)
```

## 快速开始

```bash
sudo wirepeek -i eth0
sudo wirepeek -i eth0 -f "tcp port 80"
wirepeek --read capture.pcap
sudo wirepeek --headless -i eth0 -c 100
sudo wirepeek -i eth0 --export har -o output.har
wirepeek --headless --read capture.pcap --endpoints
sudo wirepeek --headless -i eth0 --metrics-listen 127.0.0.1:9464
wirepeek --read capture.pcap --tls-keylog sslkeys.log   # 实验性：仅解析密钥，尚不解密
```

## 架构

详见[架构与设计文档](docs/zh/architecture.md)。

当前抓包处理与 UI 通过互斥锁共享状态；解析器在 libpcap 缓冲区有效期内使用零拷贝 span。
吞吐数字请先用[基准测试套件](docs/en/benchmarks.md)测量后再写入宣传材料。

## 版本规划

| 版本线 | 重点 |
|------|------|
| **v1.0.x** | 正确性：抓包时间戳、HTTP framing、链路层、DNS/TLS/WS 接线 |
| **v1.1.x** | APM：端点聚合、时延拆解、Redis、OpenMetrics、benchmark/fuzz |
| **后续** | 完整 TLS 解密（当前 keylog 为实验性）、更完整 HPACK、MySQL/PostgreSQL |

## 贡献

1. Fork 本仓库
2. 创建特性分支
3. 遵循 Google C++ Style（C++20）
4. 确保 `ctest --test-dir build` 通过
5. 发版前参考 [docs/en/release-checklist.md](docs/en/release-checklist.md)
6. 提交 Pull Request

## 许可证

本项目基于 [Apache License 2.0](LICENSE) 许可。

Copyright 2026 lucientong
