# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
