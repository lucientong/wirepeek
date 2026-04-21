# Wirepeek — Architecture & Design

> [中文版](../zh/architecture.md)

This document explains **how wirepeek is built** — the implementation strategies, key algorithms, and design trade-offs. It's intended for contributors and anyone interested in the internals.

## 1. System Overview

Wirepeek is a pipeline: raw packets flow in from one end, and structured, human-readable protocol information comes out the other.

```
Network / pcap file
    │
    ▼
┌────────────┐  PacketView     ┌──────────────┐  StreamEvent
│  Capture   │ ─────────────→  │  Dissect()   │ ──────────→
│  (libpcap) │  (zero-copy)    │  + TCP Reasm  │  (in-order)
└────────────┘                 └──────┬───────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                  ▼
             ┌───────────┐    ┌────────────┐     ┌───────────┐
             │ Protocol  │    │  Analyzer  │     │  Export   │
             │ HTTP/DNS  │    │  T-Digest  │     │ pcap/HAR │
             │ TLS/WS    │    │  Stats     │     │ JSON     │
             └─────┬─────┘    └─────┬──────┘     └──────────┘
                   │                │
                   ▼                ▼
             ┌──────────────────────────┐
             │   TUI (FTXUI) / CLI      │
             │  filter, sparkline,      │
             │  detail panel            │
             └──────────────────────────┘
```

## 2. Data Flow in Detail

A single packet's journey:

1. **libpcap** delivers a raw buffer via callback → wrapped in `PacketView` (non-owning `span`, zero allocation)
2. **`Dissect()`** chains `ParseEthernet → ParseIp → ParseTcp/ParseUdp` — each returns an `Info` struct with a `.payload` span pointing into the original buffer
3. **`TcpReassembler`** indexes by `ConnectionKey`, tracks sequence numbers, buffers out-of-order segments, emits `StreamEvent::kData` with in-order bytes
4. **`ProtocolHandler`** calls `DetectProtocol()` on first data, creates a per-stream parser (e.g., `Http1Parser`), routes subsequent data
5. **`Http1Parser`** incrementally parses request line → headers → body, pairs with response, calculates latency, emits `HttpTransaction`
6. **`Statistics`** feeds latency into `TDigest` for P50/P95/P99, tracks throughput via sliding window
7. **`UiState`** (mutex-protected) receives the entry, the TUI renders on next 100ms tick

## 3. Design Decisions

### 3.1 Zero-Copy Parsing

**Decision:** Dissectors operate on `std::span<const uint8_t>` pointing into the pcap ring buffer. No per-packet memory allocation.

**Why:** At 10Gbps (~1M packets/sec), even a 64-byte allocation per packet = 64MB/s of heap churn. By using spans, parsing is just pointer arithmetic. The trade-off: `PacketView` must not outlive the pcap buffer — that's why `OwnedPacket` exists for cross-thread handoff.

**Where:** `include/wirepeek/packet.h` (`PacketView` vs `OwnedPacket`), all dissector `Info` structs (`.payload` is a span).

### 3.2 Error Handling with DissectResult

**Decision:** `DissectResult<T>` — a `std::expected`-like type (with fallback for pre-C++23 compilers).

**Why:** Packet parsing fails often (truncated captures, corrupted data). Exceptions are too expensive on the hot path. Error codes lose type safety. `expected` gives zero-cost success path with typed errors. The `Dissect()` pipeline stops at the first failure but returns partial results — you always get as much info as possible.

**Where:** `include/wirepeek/result.h`, every `Parse*()` function.

### 3.3 TCP Reassembly with Ordered Map

**Decision:** Out-of-order segments are stored in `std::map<uint32_t, vector<uint8_t>>` keyed by sequence number.

**Why:** A contiguous ring buffer would be simpler but wastes memory for sparse arrivals. A map only stores what's actually arrived out of order. When the expected segment arrives, we scan the map for contiguous entries and flush them. Typical real-world out-of-order rate is <1%, so the map is usually empty.

**Sequence wraparound:** `static_cast<int32_t>(a - b) < 0` correctly handles the full 32-bit sequence space.

**Where:** `include/wirepeek/dissector/tcp_reassembler.h` (`HalfStream::out_of_order`), `FlushBuffered()`.

### 3.4 Protocol Detection by Content, Not Port

**Decision:** `DetectProtocol()` matches byte patterns in the first data chunk, ignoring port numbers entirely.

**Why:** Modern services run HTTP on 8080, gRPC on 50051, TLS on any port. Port-based detection is unreliable. Content-based detection (HTTP starts with `GET `, TLS starts with `0x16 0x03`) is accurate regardless of port.

**Where:** `src/protocol/detector.cpp`.

### 3.5 T-Digest for Streaming Percentiles

**Decision:** Use T-Digest (simplified) instead of keeping all values or sampling.

**Why:** Keeping all latency values for exact percentiles uses O(n) memory. Reservoir sampling loses accuracy at the tails (P99). T-Digest maintains ~100 centroids with ~1% accuracy at extreme percentiles, O(1) amortized per insertion, O(1) query. Perfect for continuous monitoring.

**Where:** `src/analyzer/tdigest.cpp`.

### 3.6 Threading: Mutex Over Lock-Free

**Decision:** Capture thread and UI thread communicate via `UiState` protected by `std::mutex`.

**Why:** Lock-free SPSC queues are faster but add complexity. At our refresh rate (10 UI frames/sec) and entry rate (~1K entries/sec), mutex contention is negligible. The critical section is tiny: copy a struct into a deque or read a deque into a vector. If profiling shows contention, upgrade to lock-free — but measure first.

**Where:** `include/wirepeek/tui/ui_state.h`.

## 4. Module Internals

### 4.1 Capture Layer

**libpcap callback model:** `pcap_loop()` blocks and invokes our callback for each packet. The callback wraps the raw `u_char*` in a `PacketView` (zero-copy) and forwards it. `Stop()` calls `pcap_breakloop()` from any thread (signal-safe via `std::atomic<bool>`).

**File vs Live:** Same `CaptureSource` interface. `FileSource` uses `pcap_next_ex()` in a loop instead of `pcap_loop()`.

### 4.2 Dissection Pipeline

Each dissector is a free function: `ParseX(span) → DissectResult<XInfo>`. The `Dissect()` orchestrator chains them:

```cpp
auto eth = ParseEthernet(packet.data);   // span into pcap buffer
auto ip  = ParseIp(eth->payload);        // span into eth's payload
auto tcp = ParseTcp(ip->payload);        // span into ip's payload
```

Every `.payload` is a sub-span — no copying at any level.

### 4.3 TCP Stream Reassembly

**Connection key normalization:** Both directions of a connection must map to the same key. We normalize by always putting the lower port in `key.src_port`. The SYN sender determines who is the "client."

**Direction detection:** Each packet's direction is determined by comparing its src\_port to the normalized key, not by tracking the SYN sender repeatedly.

**Memory protection:** Per-stream limit (10MB), max streams (1000), idle timeout (30s). When limits are hit: segments are dropped, oldest streams are evicted, idle streams are flushed.

### 4.4 HTTP/1.1 Parser

**Incremental state machine:** Data arrives in arbitrary-sized chunks from the reassembler. The parser accumulates bytes in a `std::string` buffer and parses as much as possible on each `Feed()` call.

```
kStartLine → kHeaders → kBody → kComplete → kStartLine (pipeline)
```

**Request-response pairing:** The parser maintains `has_request_` and `has_response_` flags. When both are set, it emits a `HttpTransaction` with latency = `response.timestamp - request.timestamp`.

### 4.5 DNS Parser

Operates on raw UDP payload (not via TCP reassembly). Key challenge: **name compression** — DNS names can contain pointer labels (`0xC0 xx`) that reference earlier parts of the packet. `ParseDnsName()` follows pointers recursively with a depth limit to prevent infinite loops.

### 4.6 TLS Handshake Parser

Parses only the handshake metadata (no decryption). The key value is **SNI extraction** from ClientHello extensions — this tells you which domain the client is connecting to, even though the traffic is encrypted. Extension parsing: walk the variable-length extension list, match by type ID (0x0000=SNI, 0x0010=ALPN, 0x002B=supported\_versions).

### 4.7 Statistics & T-Digest

**T-Digest compression:** When the centroid list exceeds `3 * compression` entries, merge adjacent centroids. The merge threshold depends on the centroid's quantile position — centroids near the median can absorb more, centroids at the tails stay small for accuracy.

**Throughput:** A `std::deque<ByteSample>` with 1-second sliding window. Each packet pushes `{timestamp, bytes}`. Pruning is lazy — done during `Snapshot()`.

### 4.8 Export Formats

**pcap:** Raw 24-byte file header + 16-byte per-packet header + raw bytes. Written via `write()` syscall, not buffered stdio, for signal-safety.

**HAR 1.2:** JSON structure with `log.entries[]` containing request/response pairs. Version comes from `WIREPEEK_VERSION` macro (auto-generated by CMake).

**NDJSON:** One JSON object per line. Two types: `{"type":"packet",...}` for raw packets, `{"type":"http",...}` for HTTP transactions. Designed for `jq` processing and log aggregation.

### 4.9 TUI

**FTXUI component tree:** `Renderer` produces the DOM, `CatchEvent` handles keyboard. The render function is called on every frame (~10 FPS) and rebuilds the entire DOM from `UiState`.

**Filter:** `UiState::GetFilteredEntries()` does case-insensitive substring matching on protocol/method/url fields. Filtering happens on the UI thread during render, not on the capture thread.

**Sparkline:** PPS (packets per second) is sampled every 1 second in the capture thread and pushed to `UiState::pps_history_` (60-entry rolling deque). The sparkline renders using Unicode block chars ▁▂▃▄▅▆▇█ normalized to the window's max value.

## 5. Threading Model

```
┌─ Capture Thread ────────────────┐     ┌─ UI Thread ──────────────────┐
│                                 │     │                              │
│  pcap_loop()                    │     │  FTXUI Loop (10 FPS)         │
│    │                            │     │    │                         │
│    ▼                            │     │    ▼                         │
│  Dissect() + TcpReassembler     │     │  UiState.GetFilteredEntries()│
│  + ProtocolHandler              │     │  UiState.GetStats()          │
│  + Statistics                   │     │    │                         │
│    │                            │     │    ▼                         │
│    ▼                            │     │  Render: stats bar           │
│  UiState.AddEntry() ──mutex──→──┼──→──│          sparkline           │
│  UiState.IncrementPackets()     │     │          request table       │
│  UiState.PushPpsSample()        │     │          detail panel        │
│                                 │     │          help bar            │
└─────────────────────────────────┘     └──────────────────────────────┘
```

## 6. Build System

**CMake 3.20+** with `FetchContent` for all dependencies except libpcap (system).

| Dependency | Version | Purpose |
|------------|---------|---------|
| libpcap | system | Packet capture |
| fmt | 10.2.1 | String formatting |
| spdlog | 1.14.1 | Logging |
| CLI11 | 2.4.2 | CLI argument parsing |
| xxHash | 0.8.3 | Fast hashing |
| FTXUI | 5.0.0 | Terminal UI |
| GoogleTest | 1.15.2 | Unit testing |

**Version management:** `project(VERSION x.y.z)` is the single source of truth. `configure_file()` generates `version.h` with `WIREPEEK_VERSION` macro. No hardcoded version strings anywhere.

**Build targets:** `wirepeek` (executable), `wirepeek_lib` (static library shared by exe and tests), `wirepeek_tests` (165 GoogleTest cases).

## 7. Directory Structure

```
wirepeek/
├── include/wirepeek/
│   ├── capture/           # CaptureSource, PcapSource, FileSource
│   ├── dissector/         # Ethernet/IP/TCP/UDP parsers, Dissect, TcpReassembler
│   ├── protocol/          # Detector, Http1Parser, DNS, TLS, WebSocket
│   ├── analyzer/          # TDigest, Statistics
│   ├── export/            # PcapWriter, HarWriter, JsonWriter
│   ├── tui/               # UiState, TuiApp
│   ├── packet.h, stream.h, request.h, result.h, endian.h
│   └── version.h.in       # CMake template → version.h
├── src/                    # Implementations mirror include/ structure
├── tests/unit/             # 165 GoogleTest cases
├── docs/{en,zh}/           # This document
├── .github/workflows/      # CI (multi-platform) + Release (static binaries, Docker, Homebrew)
├── Dockerfile              # Alpine multi-stage → scratch image
└── CMakeLists.txt          # Root build config + FetchContent
```

## 8. Testing Strategy

**Test pyramid:**
- **Unit tests** (165): One test file per module. Hardcoded byte arrays for protocol parsers (no network or pcap files needed). Coverage: dissectors ~80%, reassembly ~95%, protocol parsers ~90%, export ~95%, UI state ~100%.
- **Integration**: CLI headless mode with `--read <pcap>` and `--export json` verifies the full pipeline.
- **CI**: Matrix build on Ubuntu 22.04/24.04 (gcc/clang) + macOS 14 (clang). Coverage uploaded to Codecov.

**What's NOT unit-tested** (by design): `PcapSource`/`FileSource` (require libpcap runtime), `TuiApp` (requires terminal), `main.cpp` (integration-level).
