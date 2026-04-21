# Wirepeek — 架构与设计

> [English Version](../en/architecture.md)

本文档详细说明 **wirepeek 的实现方式** — 包括实现策略、关键算法和设计取舍。面向贡献者和对内部实现感兴趣的读者。

## 1. 系统总览

Wirepeek 是一条流水线：原始数据包从一端流入，结构化的、人类可读的协议信息从另一端流出。

```
网络 / pcap 文件
    │
    ▼
┌────────────┐  PacketView     ┌──────────────┐  StreamEvent
│  抓包层    │ ─────────────→  │  Dissect()   │ ──────────→
│  (libpcap) │  (零拷贝)       │  + TCP 重组   │  (有序)
└────────────┘                 └──────┬───────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                  ▼
             ┌───────────┐    ┌────────────┐     ┌───────────┐
             │ 协议解析   │    │  分析引擎  │     │  导出     │
             │ HTTP/DNS  │    │  T-Digest  │     │ pcap/HAR │
             │ TLS/WS    │    │  统计      │     │ JSON     │
             └─────┬─────┘    └─────┬──────┘     └──────────┘
                   │                │
                   ▼                ▼
             ┌──────────────────────────┐
             │   TUI (FTXUI) / CLI      │
             │  过滤、火花图、           │
             │  详情面板                 │
             └──────────────────────────┘
```

## 2. 数据流详解

一个数据包的完整旅程：

1. **libpcap** 通过回调函数传递原始缓冲区 → 封装为 `PacketView`（非拥有 `span`，零分配）
2. **`Dissect()`** 串联 `ParseEthernet → ParseIp → ParseTcp/ParseUdp` — 每个函数返回 `Info` 结构体，其中 `.payload` span 指向原始缓冲区
3. **`TcpReassembler`** 以 `ConnectionKey` 为索引，跟踪序列号，缓冲乱序段，发出带有有序字节的 `StreamEvent::kData`
4. **`ProtocolHandler`** 对首次数据调用 `DetectProtocol()`，创建每流解析器（如 `Http1Parser`），路由后续数据
5. **`Http1Parser`** 增量解析请求行 → 头部 → 正文，配对响应，计算延迟，产出 `HttpTransaction`
6. **`Statistics`** 将延迟值送入 `TDigest` 计算 P50/P95/P99，通过滑动窗口跟踪吞吐量
7. **`UiState`**（mutex 保护）接收条目，TUI 在下一个 100ms 刷新周期渲染

## 3. 设计决策

### 3.1 零拷贝解析

**决策：** 解析器操作指向 pcap 环形缓冲区的 `std::span<const uint8_t>`。不做任何逐包内存分配。

**原因：** 在 10Gbps（约 100 万包/秒）下，即使每包分配 64 字节 = 64MB/s 的堆内存压力。使用 span 后，解析就是纯指针运算。代价是：`PacketView` 不能比 pcap 缓冲区存活更久 — 这就是 `OwnedPacket` 用于跨线程传递的原因。

**位置：** `include/wirepeek/packet.h`（`PacketView` vs `OwnedPacket`），所有解析器 `Info` 结构体（`.payload` 是 span）。

### 3.2 基于 DissectResult 的错误处理

**决策：** `DissectResult<T>` — 类似 `std::expected` 的类型（兼容 C++23 之前的编译器）。

**原因：** 数据包解析经常失败（截断抓包、损坏数据）。异常在热路径上太昂贵。错误码缺乏类型安全。`expected` 提供零开销的成功路径和类型化的错误。`Dissect()` 管道在首次失败时停止，但返回部分结果 — 你总是能获得尽可能多的信息。

**位置：** `include/wirepeek/result.h`，每个 `Parse*()` 函数。

### 3.3 基于有序 Map 的 TCP 重组

**决策：** 乱序段存储在以序列号为键的 `std::map<uint32_t, vector<uint8_t>>` 中。

**原因：** 连续环形缓冲区更简单但会为稀疏到达浪费内存。Map 只存储实际乱序到达的数据。当期望的段到达时，扫描 map 中的连续条目并刷出。真实场景中典型乱序率 <1%，所以 map 通常为空。

**序列号回绕：** `static_cast<int32_t>(a - b) < 0` 正确处理完整的 32 位序列号空间。

**位置：** `include/wirepeek/dissector/tcp_reassembler.h`（`HalfStream::out_of_order`），`FlushBuffered()`。

### 3.4 基于内容而非端口的协议检测

**决策：** `DetectProtocol()` 匹配首个数据块中的字节模式，完全忽略端口号。

**原因：** 现代服务在 8080 上跑 HTTP，在 50051 上跑 gRPC，TLS 可以在任意端口。基于端口的检测不可靠。基于内容的检测（HTTP 以 `GET ` 开头，TLS 以 `0x16 0x03` 开头）无论端口如何都准确。

**位置：** `src/protocol/detector.cpp`。

### 3.5 T-Digest 流式百分位计算

**决策：** 使用 T-Digest（简化版）而非保留所有值或采样。

**原因：** 保留所有延迟值做精确百分位使用 O(n) 内存。蓄水池采样在尾部（P99）失去精度。T-Digest 维护约 100 个中心点，在极端百分位上有约 1% 的精度，插入 O(1) 摊还，查询 O(1)。非常适合持续监控。

**位置：** `src/analyzer/tdigest.cpp`。

### 3.6 线程：选择 Mutex 而非无锁

**决策：** 抓包线程和 UI 线程通过 `std::mutex` 保护的 `UiState` 通信。

**原因：** 无锁 SPSC 队列更快但增加复杂性。在我们的刷新率（10 UI 帧/秒）和条目率（约 1K 条目/秒）下，mutex 竞争可忽略不计。临界区极小：拷贝一个结构体到 deque 或从 deque 读取到 vector。如果 profiling 显示竞争，再升级为无锁 — 但先测量。

**位置：** `include/wirepeek/tui/ui_state.h`。

## 4. 模块内部实现

### 4.1 抓包层

**libpcap 回调模型：** `pcap_loop()` 阻塞并为每个数据包调用我们的回调。回调将原始 `u_char*` 封装为 `PacketView`（零拷贝）并转发。`Stop()` 从任意线程调用 `pcap_breakloop()`（通过 `std::atomic<bool>` 保证信号安全）。

**文件 vs 实时：** 相同的 `CaptureSource` 接口。`FileSource` 用 `pcap_next_ex()` 循环代替 `pcap_loop()`。

### 4.2 解析管道

每个解析器是一个自由函数：`ParseX(span) → DissectResult<XInfo>`。`Dissect()` 编排器串联它们：

```cpp
auto eth = ParseEthernet(packet.data);   // span 指向 pcap 缓冲区
auto ip  = ParseIp(eth->payload);        // span 指向 eth 的 payload
auto tcp = ParseTcp(ip->payload);        // span 指向 ip 的 payload
```

每个 `.payload` 都是子 span — 任何层级都不拷贝。

### 4.3 TCP 流重组

**连接键规范化：** 一个连接的两个方向必须映射到相同的键。我们通过始终将较小端口放在 `key.src_port` 来规范化。SYN 发送方决定谁是"客户端"。

**方向检测：** 每个数据包的方向通过比较其 src\_port 与规范化键来确定，而非反复跟踪 SYN 发送方。

**内存保护：** 单流限制（10MB），最大流数（1000），空闲超时（30s）。触发限制时：丢弃段、驱逐最老的流、刷出空闲流。

### 4.4 HTTP/1.1 解析器

**增量状态机：** 数据以任意大小的块从重组器到达。解析器在 `std::string` 缓冲区中累积字节，每次 `Feed()` 调用时尽可能多地解析。

```
kStartLine → kHeaders → kBody → kComplete → kStartLine（管线化）
```

**请求-响应配对：** 解析器维护 `has_request_` 和 `has_response_` 标志。两者都设置时，产出 `HttpTransaction`，延迟 = `response.timestamp - request.timestamp`。

### 4.5 DNS 解析器

直接操作 UDP 负载（不经过 TCP 重组）。核心挑战：**名称压缩** — DNS 名称可以包含指针标签（`0xC0 xx`），引用数据包中较早的部分。`ParseDnsName()` 递归跟随指针并设置深度限制以防止无限循环。

### 4.6 TLS 握手解析器

仅解析握手元数据（不解密）。核心价值是从 ClientHello 扩展中提取 **SNI** — 这告诉你客户端正在连接哪个域名，即使流量是加密的。扩展解析：遍历变长扩展列表，按类型 ID 匹配（0x0000=SNI，0x0010=ALPN，0x002B=supported\_versions）。

### 4.7 统计与 T-Digest

**T-Digest 压缩：** 当中心点列表超过 `3 * compression` 个条目时，合并相邻中心点。合并阈值取决于中心点的分位数位置 — 靠近中位数的中心点可以吸收更多，尾部的中心点保持较小以保证精度。

**吞吐量：** 一个 `std::deque<ByteSample>` 配合 1 秒滑动窗口。每个数据包推入 `{timestamp, bytes}`。清理是惰性的 — 在 `Snapshot()` 期间执行。

### 4.8 导出格式

**pcap：** 原始 24 字节文件头 + 16 字节逐包头 + 原始字节。通过 `write()` 系统调用写入，不使用缓冲 stdio，以保证信号安全。

**HAR 1.2：** JSON 结构包含 `log.entries[]`，含请求/响应对。版本来自 `WIREPEEK_VERSION` 宏（由 CMake 自动生成）。

**NDJSON：** 每行一个 JSON 对象。两种类型：`{"type":"packet",...}` 用于原始数据包，`{"type":"http",...}` 用于 HTTP 事务。专为 `jq` 处理和日志聚合设计。

### 4.9 TUI

**FTXUI 组件树：** `Renderer` 生成 DOM，`CatchEvent` 处理键盘事件。渲染函数在每帧（约 10 FPS）被调用，从 `UiState` 重建整个 DOM。

**过滤：** `UiState::GetFilteredEntries()` 对协议/方法/URL 字段做大小写不敏感的子串匹配。过滤在 UI 线程的渲染期间执行，不在抓包线程。

**火花图：** PPS（每秒数据包数）在抓包线程中每 1 秒采样一次并推送到 `UiState::pps_history_`（60 个条目的滚动 deque）。火花图使用 Unicode 方块字符 ▁▂▃▄▅▆▇█ 渲染，归一化到窗口最大值。

## 5. 线程模型

```
┌─ 抓包线程 ─────────────────────┐     ┌─ UI 线程 ───────────────────┐
│                                 │     │                              │
│  pcap_loop()                    │     │  FTXUI Loop (10 FPS)         │
│    │                            │     │    │                         │
│    ▼                            │     │    ▼                         │
│  Dissect() + TcpReassembler     │     │  UiState.GetFilteredEntries()│
│  + ProtocolHandler              │     │  UiState.GetStats()          │
│  + Statistics                   │     │    │                         │
│    │                            │     │    ▼                         │
│    ▼                            │     │  渲染: 统计栏                │
│  UiState.AddEntry() ──mutex──→──┼──→──│        火花图                │
│  UiState.IncrementPackets()     │     │        请求表格              │
│  UiState.PushPpsSample()        │     │        详情面板              │
│                                 │     │        帮助栏                │
└─────────────────────────────────┘     └──────────────────────────────┘
```

## 6. 构建系统

**CMake 3.20+** 配合 `FetchContent` 管理所有依赖，libpcap 除外（系统安装）。

| 依赖 | 版本 | 用途 |
|------|------|------|
| libpcap | 系统 | 数据包捕获 |
| fmt | 10.2.1 | 字符串格式化 |
| spdlog | 1.14.1 | 日志 |
| CLI11 | 2.4.2 | 命令行参数解析 |
| xxHash | 0.8.3 | 快速哈希 |
| FTXUI | 5.0.0 | 终端 UI |
| GoogleTest | 1.15.2 | 单元测试 |

**版本号管理：** `project(VERSION x.y.z)` 是唯一的版本号来源。`configure_file()` 生成包含 `WIREPEEK_VERSION` 宏的 `version.h`。项目中没有任何硬编码的版本字符串。

**构建目标：** `wirepeek`（可执行文件）、`wirepeek_lib`（静态库，被可执行文件和测试共享）、`wirepeek_tests`（165 个 GoogleTest 用例）。

## 7. 目录结构

```
wirepeek/
├── include/wirepeek/
│   ├── capture/           # CaptureSource, PcapSource, FileSource
│   ├── dissector/         # Ethernet/IP/TCP/UDP 解析器, Dissect, TcpReassembler
│   ├── protocol/          # 检测器, Http1Parser, DNS, TLS, WebSocket
│   ├── analyzer/          # TDigest, Statistics
│   ├── export/            # PcapWriter, HarWriter, JsonWriter
│   ├── tui/               # UiState, TuiApp
│   ├── packet.h, stream.h, request.h, result.h, endian.h
│   └── version.h.in       # CMake 模板 → version.h
├── src/                    # 实现文件，目录结构与 include/ 对应
├── tests/unit/             # 165 个 GoogleTest 用例
├── docs/{en,zh}/           # 本文档
├── .github/workflows/      # CI（多平台）+ Release（静态二进制、Docker、Homebrew）
├── Dockerfile              # Alpine 多阶段构建 → scratch 镜像
└── CMakeLists.txt          # 根构建配置 + FetchContent
```

## 8. 测试策略

**测试金字塔：**
- **单元测试**（165 个）：每个模块一个测试文件。协议解析器使用硬编码字节数组（不需要网络或 pcap 文件）。覆盖率：解析器约 80%，重组约 95%，协议解析器约 90%，导出约 95%，UI 状态约 100%。
- **集成测试**：CLI 无头模式配合 `--read <pcap>` 和 `--export json` 验证完整管道。
- **CI**：矩阵构建覆盖 Ubuntu 22.04/24.04（gcc/clang）+ macOS 14（clang）。覆盖率上传至 Codecov。

**故意不做单元测试的部分：** `PcapSource`/`FileSource`（需要 libpcap 运行时）、`TuiApp`（需要终端）、`main.cpp`（集成级别）。
