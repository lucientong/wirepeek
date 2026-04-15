# Wirepeek

**Peek into the wire** — A high-performance network packet analyzer with a modern TUI. What [btop](https://github.com/aristocratos/btop) is to top, Wirepeek is to tcpdump.

[![CI](https://github.com/lucientong/wirepeek/actions/workflows/ci.yml/badge.svg)](https://github.com/lucientong/wirepeek/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lucientong/wirepeek.svg)](https://github.com/lucientong/wirepeek/releases/latest)
[![Codecov](https://codecov.io/gh/lucientong/wirepeek/branch/master/graph/badge.svg)](https://codecov.io/gh/lucientong/wirepeek)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/lucientong/wirepeek)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](https://github.com/lucientong/wirepeek/blob/master/LICENSE)

[中文文档](README.zh-CN.md) · [Architecture](docs/en/architecture.md) · [Changelog](CHANGELOG.md)

## Why Wirepeek?

| Problem | Existing Tools | Wirepeek |
|---------|---------------|----------|
| **Unreadable output** | tcpdump shows raw hex dumps and TCP flags | Auto-reassembles streams, shows `GET /api → 200 OK (43ms)` |
| **GUI required** | Wireshark needs a desktop — unusable over SSH | Modern TUI (FTXUI) works in any terminal, SSH, tmux, Docker |
| **Port-based filtering only** | tcpdump requires `port 80` for HTTP | Heuristic protocol detection — identifies HTTP on any port |
| **No latency analysis** | Need external scripts to calculate timing | Built-in P50/P95/P99 latency with T-Digest, real-time charts |
| **GC pauses drop packets** | Go-based alternatives (termshark) lose packets at high throughput | C++ zero-copy parsing, lock-free queues, handles 10Gbps+ |

## Features

- **Auto Protocol Detection** — HTTP/1.1, HTTP/2, gRPC, WebSocket, DNS, TLS, MySQL, Redis
- **Request/Response View** — See URL, method, status code, headers, body — not raw bytes
- **Built-in Latency Analysis** — Request→Response time, TCP/TLS handshake duration, P50/P95/P99
- **Modern TUI** — Scrollable lists, detail panels, real-time traffic charts, interactive filters
- **Zero-Copy Parsing** — Pointer arithmetic on mmap'd ring buffer, no per-packet allocation
- **Export Formats** — pcap (Wireshark), HAR (browser), JSON (scripting/CI)
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
# Download .deb from releases
curl -LO https://github.com/lucientong/wirepeek/releases/latest/download/wirepeek_amd64.deb
sudo dpkg -i wirepeek_amd64.deb
```

### Build from Source

```bash
# Prerequisites: CMake 3.20+, C++20 compiler, libpcap-dev
# Ubuntu/Debian:
sudo apt install build-essential cmake libpcap-dev

# macOS:
brew install cmake

# Build
git clone https://github.com/lucientong/wirepeek.git
cd wirepeek
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# Install
sudo cmake --install build
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

# Filter by protocol
sudo wirepeek -i eth0 --protocol http

# Export as HAR
sudo wirepeek -i eth0 --export har -o output.har
```

### Example Output (Headless Mode)

```
14:32:01.482910  192.168.1.10:54312 -> 93.184.216.34:80 TCP [SYN] len=0
14:32:01.523847  93.184.216.34:80 -> 192.168.1.10:54312 TCP [SYN, ACK] len=0
14:32:01.523901  192.168.1.10:54312 -> 93.184.216.34:80 TCP [ACK] len=0
14:32:01.524102  192.168.1.10:54312 -> 93.184.216.34:80 TCP [PSH, ACK] len=73
14:32:01.565432  93.184.216.34:80 -> 192.168.1.10:54312 TCP [ACK] len=1256
```

## Architecture

See [Architecture Documentation](docs/en/architecture.md) for detailed design.

```
┌─────────────────────────────────────────────────────┐
│                    CLI / TUI                         │
├──────────┬──────────┬──────────┬────────────────────┤
│ Capture  │ Dissector│ Protocol │    Analyzer         │
│ (libpcap)│ (L2-L4)  │ (L7)     │ (latency/stats)    │
├──────────┴──────────┴──────────┴────────────────────┤
│              Core Types (zero-copy)                  │
└─────────────────────────────────────────────────────┘
```

## Development Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Capture + basic dissectors (Ethernet/IP/TCP/UDP) | ✅ Done |
| 2 | TCP stream reassembly | ⬜ Planned |
| 3 | HTTP/1.1 parsing + protocol detection | ⬜ Planned |
| 4 | TUI (FTXUI) | ⬜ Planned |
| 5 | Latency analysis + statistics | ⬜ Planned |
| 6 | HTTP/2, gRPC, DNS, TLS, WebSocket | ⬜ Planned |
| 7 | Export (pcap/HAR/JSON) | ⬜ Planned |
| 8 | TUI polish + filters + charts | ⬜ Planned |

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Follow [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html) with C++20 extensions
4. Ensure all tests pass (`ctest --test-dir build`)
5. Submit a Pull Request

## License

This project is licensed under the [Apache License 2.0](LICENSE).

Copyright 2026 lucientong
