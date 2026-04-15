# Wirepeek Architecture

> [中文版](../zh/architecture.md)

## Overview

Wirepeek is a single-binary, high-performance network packet analyzer designed for the terminal. It captures packets from network interfaces or pcap files, parses them through a layered dissection pipeline, and presents the results through a modern TUI or headless text output.

```
                              ┌───────────────────────┐
                              │    CLI / TUI Layer     │
                              │  (CLI11 + FTXUI)       │
                              └───────────┬───────────┘
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    │                     │                     │
              ┌─────▼─────┐        ┌──────▼──────┐      ┌──────▼──────┐
              │  Export    │        │  Analyzer   │      │  Protocol   │
              │ pcap/HAR/ │        │  latency/   │      │  HTTP/gRPC/ │
              │ JSON       │        │  statistics │      │  DNS/TLS    │
              └────────────┘        └──────┬──────┘      └──────┬──────┘
                                          │                     │
                                   ┌──────▼─────────────────────▼──────┐
                                   │         Dissector Layer            │
                                   │  Ethernet → IP → TCP / UDP        │
                                   │  (+ TCP stream reassembly)         │
                                   └──────────────┬────────────────────┘
                                                  │
                                   ┌──────────────▼────────────────────┐
                                   │         Capture Layer              │
                                   │  libpcap (live) / file reader      │
                                   └───────────────────────────────────┘
```

## Module Breakdown

### 1. Capture Layer (`src/capture/`)

Responsible for acquiring raw packet data from the operating system.

| Component | File | Description |
|-----------|------|-------------|
| `CaptureSource` | `capture.h` | Abstract base class defining the capture interface |
| `PcapSource` | `pcap_source.h/.cpp` | Live capture via libpcap (`pcap_create` → `pcap_activate` → `pcap_loop`) |
| `FileSource` | `file_source.h/.cpp` | Offline reading from `.pcap`/`.pcapng` files |

**Key design decisions:**
- **Callback-based delivery**: `Start(PacketCallback)` blocks and invokes the callback for each packet. This avoids ring buffer management in the capture layer.
- **Custom deleter**: `pcap_t*` is wrapped in `std::unique_ptr` with a custom deleter to ensure cleanup.
- **Atomic stop flag**: `Stop()` sets `std::atomic<bool>` and calls `pcap_breakloop()`, safe to call from signal handlers.

### 2. Core Types (`include/wirepeek/`)

Foundation types shared across all layers.

| Type | File | Description |
|------|------|-------------|
| `PacketView` | `packet.h` | Non-owning view into capture buffer (hot path) |
| `OwnedPacket` | `packet.h` | Owning copy for async/cross-thread use |
| `Timestamp` | `packet.h` | `std::chrono::time_point` with microsecond precision |
| `DissectResult<T>` | `result.h` | `std::expected`-like error handling for dissectors |
| `DissectError` | `result.h` | Error enum: `kTruncated`, `kInvalidHeader`, etc. |
| `ConnectionKey` | `stream.h` | 5-tuple (IPs + ports + protocol) for flow identification |
| `ReadU16Be/ReadU32Be` | `endian.h` | Network byte order reading helpers |

**Zero-copy architecture:**

```
┌──────────────────────────────────────────┐
│          libpcap ring buffer             │
│  ┌─────────────────────────────────┐     │
│  │  ethernet  │  ip  │ tcp │ data  │     │
│  └─────────────────────────────────┘     │
│       ▲            ▲        ▲            │
│       │            │        │            │
│  PacketView   IpInfo    TcpInfo          │
│  .data        .payload  .payload         │
│  (span)       (span)    (span)           │
└──────────────────────────────────────────┘
```

All `Info` structs hold `std::span<const uint8_t>` pointing into the original buffer — no copying during dissection.

### 3. Dissector Layer (`src/dissector/`)

Parses network protocol headers in a bottom-up pipeline: L2 → L3 → L4.

| Dissector | Input | Output | Key Logic |
|-----------|-------|--------|-----------|
| `ParseEthernet()` | Raw frame | `EthernetInfo` | MAC addresses, EtherType, 802.1Q VLAN |
| `ParseIp()` | Ethernet payload | `IpInfo` | IPv4 (variable IHL) / IPv6 (fixed 40B), auto-detect |
| `ParseTcp()` | IP payload | `TcpInfo` | Ports, seq/ack, flags, data offset |
| `ParseUdp()` | IP payload | `UdpInfo` | Ports, length |
| `Dissect()` | `PacketView` | `DissectedPacket` | Chains all parsers, stops at first unsupported layer |

**Error handling strategy:**

Every dissector returns `DissectResult<T>` (an `expected`-like type). On error, the pipeline stops and returns partial results — you always get as much information as possible.

```cpp
DissectResult<EthernetInfo> ParseEthernet(std::span<const uint8_t> data);
// Returns Unexpected(DissectError::kTruncated) if data.size() < 14
```

### 4. Protocol Layer (`src/protocol/`) — Phase 3+

Application-layer protocol parsing (not yet implemented).

| Protocol | Detection Heuristic | Description |
|----------|-------------------|-------------|
| HTTP/1.1 | Starts with `GET`/`POST`/`HTTP` | Request/response parsing |
| HTTP/2 | Connection preface `PRI * HTTP/2.0` | Frame-level parsing (HEADERS, DATA) |
| gRPC | HTTP/2 + `content-type: application/grpc` | Protobuf length-delimited messages |
| DNS | UDP port 53 or payload structure | Query/response parsing |
| TLS | First byte `0x16` (handshake) | ClientHello/ServerHello analysis |
| WebSocket | HTTP Upgrade header | Frame parsing after handshake |

**Smart detection** (`detector.cpp`): Checks payload byte patterns first (content-based), uses port numbers as secondary hints.

### 5. Analyzer Layer (`src/analyzer/`) — Phase 5+

Statistical analysis and latency computation (not yet implemented).

- **Latency calculator**: Correlates request → response pairs, computes time deltas
- **T-Digest**: Streaming percentile estimation (P50/P95/P99) with O(1) amortized updates
- **Connection tracker**: Lifecycle management for TCP connections (SYN → ESTABLISHED → FIN)

### 6. TUI Layer (`src/tui/`) — Phase 4+

Terminal user interface built with FTXUI (not yet implemented).

```
┌─ Traffic ───────────────────────────────┐
│  QPS: ▁▂▃▅▇█▇▅▃▂  BW: ▂▃▅▇█▇▅▃▁      │
├─ Requests ──────────────────────────────┤
│  Time     Proto  Method  URL     Status │
│  14:32:01 HTTP   GET     /api    200    │
│  14:32:01 HTTP   POST    /login  401    │
│> 14:32:02 gRPC   Unary   /svc    OK     │
├─ Detail ────────────────────────────────┤
│  Headers:                                │
│    Content-Type: application/json        │
│  Body:                                   │
│    {"user": "admin", "role": "root"}     │
└─────────────────────────────────────────┘
```

### 7. Export Layer (`src/export/`) — Phase 7

Export captured data in standard formats (not yet implemented).

| Format | Use Case |
|--------|----------|
| pcap | Open in Wireshark for deep analysis |
| HAR | Import into browser DevTools, Postman |
| JSON | Scripting, CI pipelines, log aggregation |

## Threading Model

### Phase 1 (Current): Single-Threaded

```
Main Thread: capture → dissect → print (headless)
```

### Phase 4+ (Planned): Multi-Threaded

```
Capture Thread ──► Lock-free Queue ──► Analysis Thread ──► UI Thread
     │                                       │
     │            (SPSC ring buffer)         │
     └─ pcap_loop()                          └─ FTXUI event loop
```

- **Capture thread**: Calls `pcap_loop()`, enqueues `OwnedPacket` into a lock-free SPSC queue
- **Analysis thread**: Dequeues packets, runs dissection + protocol parsing + latency calculation
- **UI thread**: FTXUI event loop, reads from shared state with atomic/mutex protection

## Data Flow

```
Network Interface
       │
       ▼
  ┌─────────┐     PacketView (zero-copy)
  │ libpcap ├──────────────────────────┐
  └─────────┘                          │
                                       ▼
                               ┌──────────────┐
                               │ ParseEthernet│
                               └──────┬───────┘
                                      │ EthernetInfo.payload
                                      ▼
                               ┌──────────────┐
                               │   ParseIp    │
                               └──────┬───────┘
                                      │ IpInfo.payload
                            ┌─────────┴─────────┐
                            ▼                   ▼
                     ┌────────────┐      ┌────────────┐
                     │  ParseTcp  │      │  ParseUdp  │
                     └──────┬─────┘      └──────┬─────┘
                            │                   │
                            ▼                   ▼
                     ┌────────────────────────────────┐
                     │    Application Protocol         │
                     │    Detection + Parsing           │
                     │    (HTTP, gRPC, DNS, ...)        │
                     └────────────────────────────────┘
                                      │
                            ┌─────────┴─────────┐
                            ▼                   ▼
                     ┌────────────┐      ┌────────────┐
                     │  Analyzer  │      │   Export    │
                     │  (latency) │      │  (HAR/JSON) │
                     └──────┬─────┘      └────────────┘
                            │
                            ▼
                     ┌────────────┐
                     │  TUI / CLI │
                     └────────────┘
```

## Build System

The project uses CMake with FetchContent for dependency management:

| Dependency | Version | Purpose |
|------------|---------|---------|
| libpcap | system | Packet capture |
| fmt | 10.2.1 | String formatting |
| spdlog | 1.14.1 | Logging |
| CLI11 | 2.4.2 | Command-line parsing |
| xxHash | 0.8.3 | Fast hashing (connection table) |
| FTXUI | 5.0.0 | Terminal UI framework |
| GoogleTest | 1.15.2 | Unit testing |

Build targets:
- `wirepeek` — main executable
- `wirepeek_lib` — static library (shared between executable and tests)
- `wirepeek_tests` — GoogleTest test binary

## Performance Design Principles

1. **Zero-copy parsing**: Dissectors operate on `std::span` into the pcap buffer — no memory allocation per packet
2. **Cache-friendly layout**: `PacketView` and `Info` structs are small, contiguous, and fit in cache lines
3. **Lock-free communication**: SPSC ring buffer between capture and analysis threads (planned)
4. **Batch processing**: Amortize overhead by processing packets in batches (planned)
5. **SIMD acceleration**: Protocol header field extraction using SIMD intrinsics where applicable (planned)

## Directory Structure

```
wirepeek/
├── include/wirepeek/           # Public headers
│   ├── capture/                # Capture source interfaces
│   ├── dissector/              # Protocol dissector headers
│   ├── packet.h                # Core packet types
│   ├── result.h                # Error handling
│   ├── endian.h                # Byte order utilities
│   ├── stream.h                # TCP stream types
│   └── request.h               # Application-layer request types
├── src/
│   ├── capture/                # libpcap capture implementation
│   ├── dissector/              # Protocol dissector implementations
│   ├── cli/                    # CLI entry point
│   └── CMakeLists.txt
├── tests/
│   ├── unit/                   # Unit tests (GoogleTest)
│   └── pcaps/                  # Test capture files
├── docs/
│   ├── en/                     # English documentation
│   └── zh/                     # Chinese documentation
├── cmake/                      # CMake modules (FindPcap.cmake)
├── .github/workflows/          # CI/CD pipelines
├── CMakeLists.txt              # Root build configuration
├── CHANGELOG.md
├── LICENSE                     # Apache 2.0
├── README.md                   # English README
└── README.zh-CN.md             # Chinese README
```
