# Wirepeek 架构文档

> [English Version](../en/architecture.md)

## 概述

Wirepeek 是一个单二进制、高性能的网络数据包分析器，专为终端环境设计。它从网络接口或 pcap 文件捕获数据包，通过分层解析管道进行解析，并通过现代化 TUI 或无头文本模式呈现结果。

```
                              ┌───────────────────────┐
                              │    CLI / TUI 层        │
                              │  (CLI11 + FTXUI)       │
                              └───────────┬───────────┘
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    │                     │                     │
              ┌─────▼─────┐        ┌──────▼──────┐      ┌──────▼──────┐
              │  导出模块   │        │  分析引擎   │      │  应用层协议  │
              │ pcap/HAR/ │        │  延迟/统计   │      │  HTTP/gRPC/ │
              │ JSON       │        │             │      │  DNS/TLS    │
              └────────────┘        └──────┬──────┘      └──────┬──────┘
                                          │                     │
                                   ┌──────▼─────────────────────▼──────┐
                                   │           协议解析层               │
                                   │  Ethernet → IP → TCP / UDP        │
                                   │  (+ TCP 流重组)                    │
                                   └──────────────┬────────────────────┘
                                                  │
                                   ┌──────────────▼────────────────────┐
                                   │           抓包层                   │
                                   │  libpcap (实时) / 文件读取         │
                                   └───────────────────────────────────┘
```

## 模块详解

### 1. 抓包层 (`src/capture/`)

负责从操作系统获取原始数据包。

| 组件 | 文件 | 描述 |
|------|------|------|
| `CaptureSource` | `capture.h` | 抽象基类，定义抓包接口 |
| `PcapSource` | `pcap_source.h/.cpp` | 通过 libpcap 实时抓包 (`pcap_create` → `pcap_activate` → `pcap_loop`) |
| `FileSource` | `file_source.h/.cpp` | 离线读取 `.pcap`/`.pcapng` 文件 |

**关键设计决策：**
- **回调式投递**：`Start(PacketCallback)` 阻塞执行并为每个数据包调用回调，避免在抓包层管理环形缓冲区
- **自定义删除器**：`pcap_t*` 用 `std::unique_ptr` 配合自定义删除器包装，确保资源清理
- **原子停止标志**：`Stop()` 设置 `std::atomic<bool>` 并调用 `pcap_breakloop()`，可安全从信号处理器调用

### 2. 核心类型 (`include/wirepeek/`)

所有层共享的基础类型。

| 类型 | 文件 | 描述 |
|------|------|------|
| `PacketView` | `packet.h` | 非拥有视图，指向抓包缓冲区（热路径） |
| `OwnedPacket` | `packet.h` | 拥有所有权的拷贝，用于异步/跨线程场景 |
| `Timestamp` | `packet.h` | `std::chrono::time_point`，微秒精度 |
| `DissectResult<T>` | `result.h` | 类 `std::expected` 的错误处理 |
| `DissectError` | `result.h` | 错误枚举：`kTruncated`、`kInvalidHeader` 等 |
| `ConnectionKey` | `stream.h` | 五元组 (IP + 端口 + 协议) 用于流识别 |
| `ReadU16Be/ReadU32Be` | `endian.h` | 网络字节序读取辅助函数 |

**零拷贝架构：**

```
┌──────────────────────────────────────────┐
│          libpcap 环形缓冲区               │
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

所有 `Info` 结构体持有 `std::span<const uint8_t>` 指向原始缓冲区 — 解析过程中零拷贝。

### 3. 协议解析层 (`src/dissector/`)

自底向上解析网络协议头：L2 → L3 → L4。

| 解析器 | 输入 | 输出 | 核心逻辑 |
|--------|------|------|----------|
| `ParseEthernet()` | 原始帧 | `EthernetInfo` | MAC 地址、EtherType、802.1Q VLAN |
| `ParseIp()` | 以太网载荷 | `IpInfo` | IPv4 (可变 IHL) / IPv6 (固定 40B)，自动检测 |
| `ParseTcp()` | IP 载荷 | `TcpInfo` | 端口、seq/ack、标志位、数据偏移 |
| `ParseUdp()` | IP 载荷 | `UdpInfo` | 端口、长度 |
| `Dissect()` | `PacketView` | `DissectedPacket` | 串联所有解析器，在首个不支持的层停止 |

**错误处理策略：**

每个解析器返回 `DissectResult<T>`（类 `expected` 类型）。出错时管道停止并返回部分结果 — 总是尽可能多地提供信息。

```cpp
DissectResult<EthernetInfo> ParseEthernet(std::span<const uint8_t> data);
// 当 data.size() < 14 时返回 Unexpected(DissectError::kTruncated)
```

### 4. 应用层协议 (`src/protocol/`) — 第 3 阶段+

应用层协议解析（尚未实现）。

| 协议 | 检测启发式 | 描述 |
|------|-----------|------|
| HTTP/1.1 | 以 `GET`/`POST`/`HTTP` 开头 | 请求/响应解析 |
| HTTP/2 | 连接前言 `PRI * HTTP/2.0` | 帧级解析 (HEADERS, DATA) |
| gRPC | HTTP/2 + `content-type: application/grpc` | Protobuf 长度定界消息 |
| DNS | UDP 端口 53 或载荷结构 | 查询/响应解析 |
| TLS | 首字节 `0x16` (握手) | ClientHello/ServerHello 分析 |
| WebSocket | HTTP Upgrade 头 | 握手后帧解析 |

**智能检测** (`detector.cpp`)：优先检查载荷字节模式（基于内容），端口号作为辅助判断。

### 5. 分析引擎 (`src/analyzer/`) — 第 5 阶段+

统计分析和延迟计算（尚未实现）。

- **延迟计算器**：关联请求→响应对，计算时间差
- **T-Digest**：流式百分位估算 (P50/P95/P99)，均摊 O(1) 更新
- **连接追踪器**：TCP 连接生命周期管理 (SYN → ESTABLISHED → FIN)

### 6. TUI 层 (`src/tui/`) — 第 4 阶段+

基于 FTXUI 构建的终端用户界面（尚未实现）。

```
┌─ 流量 ──────────────────────────────────┐
│  QPS: ▁▂▃▅▇█▇▅▃▂  带宽: ▂▃▅▇█▇▅▃▁     │
├─ 请求列表 ──────────────────────────────┤
│  时间     协议   方法    URL     状态    │
│  14:32:01 HTTP   GET     /api    200    │
│  14:32:01 HTTP   POST    /login  401    │
│> 14:32:02 gRPC   Unary   /svc    OK     │
├─ 详情 ──────────────────────────────────┤
│  请求头:                                 │
│    Content-Type: application/json        │
│  请求体:                                 │
│    {"user": "admin", "role": "root"}     │
└─────────────────────────────────────────┘
```

### 7. 导出模块 (`src/export/`) — 第 7 阶段

以标准格式导出捕获的数据（尚未实现）。

| 格式 | 用途 |
|------|------|
| pcap | 在 Wireshark 中打开进行深度分析 |
| HAR | 导入浏览器 DevTools、Postman |
| JSON | 脚本、CI 管道、日志聚合 |

## 线程模型

### 第 1 阶段（当前）：单线程

```
主线程: 抓包 → 解析 → 输出 (无头模式)
```

### 第 4 阶段+（规划中）：多线程

```
抓包线程 ──► 无锁队列 ──► 分析线程 ──► UI 线程
     │                         │
     │    (SPSC 环形缓冲区)     │
     └─ pcap_loop()            └─ FTXUI 事件循环
```

- **抓包线程**：调用 `pcap_loop()`，将 `OwnedPacket` 入队到无锁 SPSC 队列
- **分析线程**：出队数据包，执行解析 + 协议识别 + 延迟计算
- **UI 线程**：FTXUI 事件循环，通过 atomic/mutex 保护的共享状态读取数据

## 数据流

```
网络接口
   │
   ▼
┌─────────┐     PacketView (零拷贝)
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
                   │      应用层协议检测 + 解析       │
                   │    (HTTP, gRPC, DNS, ...)       │
                   └────────────────────────────────┘
                                    │
                          ┌─────────┴─────────┐
                          ▼                   ▼
                   ┌────────────┐      ┌────────────┐
                   │  分析引擎   │      │  导出模块   │
                   │  (延迟统计) │      │ (HAR/JSON)  │
                   └──────┬─────┘      └────────────┘
                          │
                          ▼
                   ┌────────────┐
                   │  TUI / CLI │
                   └────────────┘
```

## 构建系统

项目使用 CMake + FetchContent 管理依赖：

| 依赖 | 版本 | 用途 |
|------|------|------|
| libpcap | 系统 | 数据包捕获 |
| fmt | 10.2.1 | 字符串格式化 |
| spdlog | 1.14.1 | 日志 |
| CLI11 | 2.4.2 | 命令行解析 |
| xxHash | 0.8.3 | 快速哈希（连接表） |
| FTXUI | 5.0.0 | 终端 UI 框架 |
| GoogleTest | 1.15.2 | 单元测试 |

构建目标：
- `wirepeek` — 主可执行文件
- `wirepeek_lib` — 静态库（可执行文件和测试共享）
- `wirepeek_tests` — GoogleTest 测试二进制

## 性能设计原则

1. **零拷贝解析**：解析器在 `std::span` 上操作，直接指向 pcap 缓冲区 — 每包无内存分配
2. **缓存友好布局**：`PacketView` 和 `Info` 结构体小巧、连续，适配缓存行
3. **无锁通信**：抓包和分析线程间使用 SPSC 环形缓冲区（规划中）
4. **批处理**：批量处理数据包以分摊开销（规划中）
5. **SIMD 加速**：在适用场景使用 SIMD 指令提取协议头字段（规划中）

## 目录结构

```
wirepeek/
├── include/wirepeek/           # 公共头文件
│   ├── capture/                # 抓包源接口
│   ├── dissector/              # 协议解析器头文件
│   ├── packet.h                # 核心数据包类型
│   ├── result.h                # 错误处理
│   ├── endian.h                # 字节序工具
│   ├── stream.h                # TCP 流类型
│   └── request.h               # 应用层请求类型
├── src/
│   ├── capture/                # libpcap 抓包实现
│   ├── dissector/              # 协议解析器实现
│   ├── cli/                    # CLI 入口
│   └── CMakeLists.txt
├── tests/
│   ├── unit/                   # 单元测试 (GoogleTest)
│   └── pcaps/                  # 测试抓包文件
├── docs/
│   ├── en/                     # 英文文档
│   └── zh/                     # 中文文档
├── cmake/                      # CMake 模块 (FindPcap.cmake)
├── .github/workflows/          # CI/CD 管道
├── CMakeLists.txt              # 根构建配置
├── CHANGELOG.md
├── LICENSE                     # Apache 2.0
├── README.md                   # 英文 README
└── README.zh-CN.md             # 中文 README
```
