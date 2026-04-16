# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-04-16

### Added

- **T-Digest percentile engine** (`TDigest`): Streaming percentile estimation for P50/P95/P99 latency with ~1% accuracy and O(1) amortized updates.
- **Statistics collector** (`Statistics`): Thread-safe aggregate metrics — latency percentiles, average latency, real-time throughput (Mbps, sliding 1s window), QPS, active stream count.
- **Enhanced TUI stats bar**: Now displays P95 latency and throughput alongside packet/stream/HTTP counts.
- **14 new unit tests**: T-Digest (7 tests), Statistics (7 tests). Total: 100 test cases.

## [0.4.0] - 2026-04-16

### Added

- **Terminal UI** (`TuiApp`): Modern interactive terminal interface built with FTXUI v5.0.0.
  - Stats bar: live packet count, TCP stream count, HTTP transaction count.
  - Request table: scrollable list with Time, Protocol, Method, URL, Status, Latency columns.
  - Detail panel: shows request/response headers for selected entry (toggle with `d`).
  - Color-coded: protocol names (HTTP=cyan, TLS=yellow, TCP=blue, UDP=magenta), status codes (2xx=green, 4xx=red, 5xx=dark red).
  - Keyboard navigation: `↑↓` scroll, `q` quit, `d` toggle detail panel.
  - Multi-threaded: capture runs in background thread, UI renders on main thread with 100ms refresh.
  - Thread-safe `UiState` with mutex-protected circular buffer (max 10,000 entries).
- **Default mode is now TUI** — `--headless` flag for tcpdump-like output (previous behavior).

## [0.3.0] - 2026-04-16

### Added

- **Protocol detection** (`DetectProtocol`): Heuristic-based detection from first stream bytes — HTTP/1.1 (all methods + response), TLS (handshake record), HTTP/2 (connection preface).
- **HTTP/1.1 parser** (`Http1Parser`): Incremental request/response parser with Content-Length body handling, header parsing, request-response pairing, and latency calculation.
- **Protocol handler** (`ProtocolHandler`): Routes reassembled stream data to appropriate parsers — detects protocol on first data event, creates per-stream parser instances.
- **Application-layer data model** (`request.h`): `AppProtocol` enum, `HttpRequest`, `HttpResponse`, `HttpTransaction` structs.
- **CLI HTTP output**: Displays `GET /path HTTP/1.1 → 200 OK (43ms) [1256 bytes]` for HTTP traffic, falls back to raw byte counts for non-HTTP.
- **23 new unit tests**: Protocol detection (14 tests), HTTP/1.1 parser (9 tests).

## [0.2.0] - 2026-04-15

### Added

- **TCP stream reassembly** (`TcpReassembler`): Tracks TCP connections, reorders out-of-order segments, and delivers contiguous in-order byte streams via callback.
  - 3-way handshake detection (SYN → SYN-ACK → Established).
  - Bidirectional stream tracking (client→server and server→client).
  - Out-of-order segment buffering and automatic flush when gaps are filled.
  - Retransmission detection ("first wins" strategy).
  - Connection close handling (FIN from both sides, RST immediate close).
  - Idle stream timeout with configurable expiry (default 30s).
  - Mid-flow join support (streams joined without seeing SYN).
  - Per-stream memory limits (default 10MB) and max concurrent streams (default 1000).
  - Sequence number wraparound handling via signed 32-bit comparison.
- **`StreamDirection` enum**: `kClientToServer` / `kServerToClient` in `stream.h`.
- **CLI integration**: `--no-reassemble` flag; stream events printed in headless mode.
- **10 new unit tests** for TCP reassembly: handshake, in-order delivery, out-of-order, retransmission, FIN/RST close, timeout, mid-flow join, bidirectional data, non-TCP ignore.

## [0.1.4] - 2026-04-15

### Added

- **Dissect pipeline tests**: Full end-to-end tests for `Dissect()` — TCP, UDP, ARP, truncated IP, unknown protocol, empty packet.
- **FormatSummary tests**: Verify output format for TCP, UDP, ARP, unknown protocol, and empty packets.
- **OwnedPacket tests**: Verify data copy semantics, `View()` round-trip, and empty packet handling.
- **ConnectionKey tests**: Equality, inequality, hash consistency, and `std::unordered_map` integration.
- **Additional IP tests**: IPv4 with options (IHL > 5), IPv4/IPv6 with UDP protocol, truncated IPv6.
- **Additional TCP flag tests**: All individual flags (RST, PSH, URG, ECE, CWR) and all-flags-combined.

### Changed

- Test count: 26 → 53 test cases.

## [0.1.3] - 2026-04-15
## [0.1.2] - 2026-04-15
## [0.1.1] - 2026-04-15

### Added

- nothing,just fix my CICD config.

## [0.1.0] - 2026-04-15

### Added

- **Capture engine**: Live packet capture via libpcap (`PcapSource`) and offline pcap file reading (`FileSource`).
- **Ethernet dissector**: Parse Ethernet II frames with 802.1Q VLAN tag support.
- **IP dissector**: Parse IPv4 (variable IHL) and IPv6 (fixed header) packets with auto-detection.
- **TCP dissector**: Parse TCP headers including flags, sequence/acknowledgement numbers, and data offset.
- **UDP dissector**: Parse UDP headers with length validation.
- **Dissection pipeline**: `Dissect()` chains Ethernet → IP → TCP/UDP and produces `DissectedPacket` with all layers.
- **Headless CLI**: Command-line interface with `-i` (interface), `-f` (BPF filter), `--read` (pcap file), `-c` (count), `--headless` options.
- **Zero-copy architecture**: All dissectors operate on `std::span<const uint8_t>` with no per-packet memory allocation.
- **Error handling**: `DissectResult<T>` (expected-like) with `DissectError` enum for robust error propagation.
- **Unit tests**: 26 test cases covering all dissectors with hardcoded byte array fixtures.
- **CMake build system**: FetchContent-based dependency management (fmt, spdlog, CLI11, xxHash, FTXUI, GoogleTest).
- **CI/CD**: GitHub Actions workflows for CI (multi-platform build + test) and Release (static binaries, .deb, Homebrew tap).
- **Documentation**: English and Chinese README, architecture documentation.

[Unreleased]: https://github.com/lucientong/wirepeek/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/lucientong/wirepeek/releases/tag/v0.1.0
