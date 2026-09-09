# Wirepeek

**Peek into the wire** — A high-performance network packet analyzer with a modern TUI. What [btop](https://github.com/aristocratos/btop) is to top, Wirepeek is to tcpdump.

[![CI](https://github.com/lucientong/wirepeek/actions/workflows/ci.yml/badge.svg)](https://github.com/lucientong/wirepeek/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lucientong/wirepeek.svg)](https://github.com/lucientong/wirepeek/releases/latest)
[![Codecov](https://codecov.io/gh/lucientong/wirepeek/branch/master/graph/badge.svg)](https://codecov.io/gh/lucientong/wirepeek)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/lucientong/wirepeek)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](https://github.com/lucientong/wirepeek/blob/master/LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/lucientong/wirepeek)](https://hub.docker.com/r/lucientong/wirepeek)
[![GitHub Downloads](https://img.shields.io/github/downloads/lucientong/wirepeek/total)](https://github.com/lucientong/wirepeek/releases)

[中文文档](README.zh-CN.md) · [Architecture](docs/en/architecture.md) · [Benchmarks](docs/en/benchmarks.md) · [Changelog](CHANGELOG.md)

## Why Wirepeek?

| Problem | Existing Tools | Wirepeek |
|---------|---------------|----------|
| **Unreadable output** | tcpdump shows raw hex dumps and TCP flags | Auto-reassembles streams, shows `GET /api → 200 OK (43ms)` |
| **GUI required** | Wireshark needs a desktop — unusable over SSH | Modern TUI (FTXUI) works in any terminal, SSH, tmux, Docker |
| **Port-based filtering only** | tcpdump requires `port 80` for HTTP | Heuristic protocol detection — identifies HTTP on any port |
| **No latency analysis** | Need external scripts to calculate timing | Built-in P50/P95/P99 latency with T-Digest, endpoint aggregation |
| **Predictable packet processing** | Managed runtimes can introduce garbage-collection pauses | C++ parsing with zero-copy spans into the libpcap packet buffer |

## Features

- **Application protocols** — HTTP/1.1 (chunked, pipelining, HEAD/204/304), DNS, TLS handshake metadata (SNI/ALPN), optional TLS 1.2/1.3 decryption via SSLKEYLOGFILE, WebSocket frames, Redis RESP, minimal HTTP/2 / gRPC framing
- **Request/Response View** — Method, URL, status, headers, sizes, and capture-time latency
- **Passive APM** — Normalized endpoint stats, TCP handshake / TTFB / transfer timing, OpenMetrics export
- **Modern TUI** — Scrollable lists, detail panels, sparklines, filters, pause/follow, endpoint view (`e`)
- **Link-layer support** — Ethernet, BSD NULL/LOOP, Linux SLL/SLL2, raw IP (`lo0` / `-i any` friendly)
- **Zero-Copy Packet Dissection** — Non-owning spans into the libpcap callback buffer
- **Export Formats** — pcap, HAR 1.2, NDJSON
- **Headless Mode** — tcpdump-like output for piping and scripting

## Installation

### Homebrew (macOS / Linux)

```bash
brew install lucientong/tap/wirepeek
```

### Static Binary

Download from [GitHub Releases](https://github.com/lucientong/wirepeek/releases/latest):

```bash
# Linux x86_64
curl -Lo wirepeek https://github.com/lucientong/wirepeek/releases/latest/download/wirepeek-linux-x86_64
chmod +x wirepeek && sudo mv wirepeek /usr/local/bin/

# Linux arm64
curl -Lo wirepeek https://github.com/lucientong/wirepeek/releases/latest/download/wirepeek-linux-arm64
chmod +x wirepeek && sudo mv wirepeek /usr/local/bin/

# macOS (universal)
curl -Lo wirepeek https://github.com/lucientong/wirepeek/releases/latest/download/wirepeek-macos-universal
chmod +x wirepeek && sudo mv wirepeek /usr/local/bin/
```

### AUR (Arch Linux)

```bash
yay -S wirepeek
```

### Debian / Ubuntu

```bash
curl -LO https://github.com/lucientong/wirepeek/releases/latest/download/wirepeek_amd64.deb
sudo dpkg -i wirepeek_amd64.deb
```

### Build from Source

```bash
# Prerequisites: CMake 3.20+, C++20 compiler, libpcap-dev
sudo apt install build-essential cmake libpcap-dev   # Ubuntu/Debian
brew install cmake                                   # macOS

git clone https://github.com/lucientong/wirepeek.git
cd wirepeek
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
sudo cmake --install build
```

Optional builds:

```bash
# TLS decryption (requires OpenSSL 3.x)
cmake -B build-tls -DWIREPEEK_ENABLE_TLS_DECRYPT=ON -DCMAKE_BUILD_TYPE=Release
# macOS Homebrew OpenSSL tip:
# cmake -B build-tls -DWIREPEEK_ENABLE_TLS_DECRYPT=ON -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"

cmake -B build-bench -DWIREPEEK_BUILD_BENCHMARKS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-bench -j$(nproc)

cmake -B build-fuzz -DWIREPEEK_BUILD_FUZZERS=ON -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang
cmake --build build-fuzz -j$(nproc)
```

## Quick Start

```bash
# Capture on interface (requires root/sudo)
sudo wirepeek -i eth0

# Filter with BPF expression
sudo wirepeek -i eth0 -f "tcp port 80"

# Read from pcap file
wirepeek --read capture.pcap

# Headless mode (tcpdump-like output)
sudo wirepeek --headless -i eth0 -c 100

# Export as HAR
sudo wirepeek -i eth0 --export har -o output.har

# Print normalized endpoint statistics at exit
wirepeek --headless --read capture.pcap --endpoints

# Serve Prometheus/OpenMetrics while capturing
sudo wirepeek --headless -i eth0 --metrics-listen 127.0.0.1:9464

# Decrypt TLS with SSLKEYLOGFILE (OpenSSL-enabled build only)
# Privacy: only works when you already have the process key log; never guess keys.
wirepeek --read capture.pcap --tls-keylog sslkeys.log --headless
```

### Example Output (Headless Mode)

```
14:32:01.482910  192.168.1.10:54312 -> 93.184.216.34:80 TCP [SYN] len=0
14:32:01.523847  93.184.216.34:80 -> 192.168.1.10:54312 TCP [SYN, ACK] len=0
14:32:01.524102  192.168.1.10:54312 -> 93.184.216.34:80 TCP [PSH, ACK] len=73
GET /api/users HTTP/1.1 -> 200 OK (43ms) [1256 bytes]
```

### TUI Mode (Default)

```
┌ Pkts:4821 Strm:23 HTTP:15 P95:43ms │▁▂▃▅▇█▇▅▃│ 2.3Mbps  wirepeek ┐
├ Filter: /api  (12/4821) ────────────────────────────────────────────┤
├──────────┬──────┬──────┬──────────────────┬──────┬──────────────────┤
│ Time     │Proto │Method│ URL              │Status│ Latency          │
│ 14:32:01 │ HTTP │ GET  │ /api/users       │  200 │  43ms            │
│ 14:32:01 │ HTTP │ POST │ /api/login       │  401 │  12ms            │
│>14:32:02 │ HTTP │ GET  │ /api/posts?page=2│  200 │ 120ms            │
│ 14:32:03 │ DNS  │      │ cdn.example.com  │      │                  │
├──────────┴──────┴──────┴──────────────────┴──────┴──────────────────┤
│ GET /api/posts?page=2 HTTP/1.1                                      │
│ Host: example.com                                                   │
│ → 200 OK (Content-Length: 45231)                                    │
├─────────────────────────────────────────────────────────────────────┤
│ q:quit ↑↓:nav d:detail /:filter Space:pause e:endpoints Esc:clear  │
└─────────────────────────────────────────────────────────────────────┘
```

## Architecture

```
  Network ──→ libpcap ──→ Dissect ──→ TCP Reassembly ──→ Protocol Detection
                           (L2-L4)    (reorder/dedup)     (HTTP/DNS/TLS/WS/Redis/h2)
                                                                │
                              ┌──────────────────┬──────────────┤
                              ▼                  ▼              ▼
                          Analyzer           TUI/CLI         Export
                     (T-Digest + endpoints) (FTXUI)   (pcap/HAR/JSON/metrics)
```

See [Architecture & Design Documentation](docs/en/architecture.md) for implementation details.

Capture processing and the UI currently share state through a mutex. Packet dissectors use
zero-copy spans into libpcap-provided buffers while those buffers are valid. Publish
throughput claims only after measuring with the [benchmark suite](docs/en/benchmarks.md).

## Versioning

| Line | Focus |
|------|-------|
| **v1.0.x** | Correctness: capture timestamps, HTTP framing, link types, DNS/TLS/WS wiring |
| **v1.1.x** | PassivePM: endpoint aggregation, timing breakdown, Redis, OpenMetrics, benchmarks/fuzz |
| **v1.2.x** | TLS 1.2/1.3 AEAD decryption via SSLKEYLOGFILE (optional OpenSSL build) |
| **Later** | Richer HPACK, MySQL/PostgreSQL, QUIC |

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Follow [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html) with C++20 extensions
4. Ensure all tests pass (`ctest --test-dir build`)
5. See [docs/en/release-checklist.md](docs/en/release-checklist.md) before tagging a release
6. Submit a Pull Request

## License

This project is licensed under the [Apache License 2.0](LICENSE).

Copyright 2026 lucientong
