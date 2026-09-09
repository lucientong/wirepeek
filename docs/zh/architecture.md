# Wirepeek — 架构与设计

> [English](../en/architecture.md)

本文说明 wirepeek **如何构建**：实现策略、关键算法与设计取舍。面向贡献者与关心内部实现的读者。完整细节以英文版为准；以下为与 v1.1 对齐的摘要。

## 系统概览

```
网络 / pcap
    │
    ▼
Capture (libpcap + LinkType)
    │ PacketView (zero-copy span)
    ▼
Dissect (Ethernet / NULL / SLL / RAW → IP → TCP/UDP)
    │
    ▼
TcpReassembler (乱序重组 + 捕获时间戳)
    │ StreamEvent
    ▼
ProtocolHandler → AppEvent (HTTP / DNS / TLS / WS / Redis / h2)
    │
    ├── Analyzer（T-Digest、端点聚合、OpenMetrics）
    ├── TUI / CLI
    └── Export（pcap / HAR / JSON）
```

## 关键设计决策

1. **零拷贝解析**：dissector 使用指向 libpcap 缓冲的 `std::span`；跨线程时用 `OwnedPacket`。
2. **错误处理**：热路径用 `DissectResult`（expected-like），避免异常。
3. **TCP 重组**：乱序段存 `map<seq, BufferedSegment>`（含时间戳）；计入内存配额；部分重传裁剪前缀。
4. **协议检测**：按内容而非端口；统一 `AppEvent` 输出。
5. **百分位**：会话累计 T-Digest；吞吐/QPS 为 1 秒滑动窗口速率。
6. **线程模型**：Capture ↔ UI 当前用 mutex；提供有界 `SpscQueue` 供测量后升级。吞吐数字须以 [benchmarks](../en/benchmarks.md) 为准。

## 模块索引

| 模块 | 路径 |
|------|------|
| Capture | `include/wirepeek/capture/` |
| Link / Dissect | `include/wirepeek/dissector/` |
| Protocols | `include/wirepeek/protocol/` |
| Analyzer / Metrics | `include/wirepeek/analyzer/` |
| Export | `include/wirepeek/export/` |
| TUI | `include/wirepeek/tui/` |
| Fuzz / Bench | `tests/fuzz/`, `benchmarks/` |

## 测试与发布

- 单元测试 + `tests/pcaps/` CLI 集成回放
- CI：多平台构建、ASan/UBSan、fuzz smoke
- 发版清单：[release-checklist.md](../en/release-checklist.md)

更多算法细节、序列号回绕、DNS 压缩指针、TLS 扩展解析等，见 [英文架构文档](../en/architecture.md)。
