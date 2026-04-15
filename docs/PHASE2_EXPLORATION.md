# Wirepeek Project Exploration Report

## Project Overview
**wirepeek** is a high-performance network packet analyzer with a modern TUI (Terminal User Interface). Currently in Phase 1/2 of development (capture + dissection).

**Current Status:**
- ✅ Phase 1: Packet capture (live + pcap files) 
- 🚀 Phase 2: TCP stream reassembly (in progress)
- ⏳ Phase 3: Application-layer parsing (HTTP, gRPC, DNS)
- ⏳ Phase 4: TUI visualization

---

## Current Architecture

### 1. **Data Structures for Stream Tracking**

#### `include/wirepeek/stream.h`
- **ConnectionKey** - 5-tuple identifier for streams:
  ```cpp
  struct ConnectionKey {
    std::array<uint8_t, 16> src_ip{};      // IPv4 (4 bytes) or IPv6 (16 bytes)
    std::array<uint8_t, 16> dst_ip{};
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t ip_version = 4;                // 4 or 6
    uint8_t protocol = 0;                  // 6=TCP, 17=UDP
  };
  ```
  - Uses **custom FNV-1a hash** for `std::unordered_map` storage
  - Already supports IPv4, IPv6, and bidirectional stream tracking

**What's Missing:**
- No stream-specific state tracking (connection state, buffered segments, etc.)
- No reassembly algorithm or segment reordering
- No per-stream output buffer

---

### 2. **Packet Data Structures**

#### `include/wirepeek/packet.h`
- **PacketView** - zero-copy, non-owning reference:
  ```cpp
  struct PacketView {
    std::span<const uint8_t> data;        // Pointer into pcap ring buffer
    Timestamp timestamp;                   // Microsecond precision
    uint32_t capture_length = 0;
    uint32_t original_length = 0;
  };
  ```
  
- **OwnedPacket** - copy for async processing:
  ```cpp
  struct OwnedPacket {
    std::vector<uint8_t> data;            // Owned buffer
    Timestamp timestamp;
    uint32_t original_length = 0;
    
    PacketView View() const;              // Convert to non-owning view
  };
  ```

**Key Insight:** Stream reassembly must buffer `OwnedPacket`s (not `PacketView`s) to prevent use-after-free when packets outlive capture buffer.

---

### 3. **Dissection Pipeline**

#### `include/wirepeek/dissector/dissect.h`
```cpp
struct DissectedPacket {
  std::optional<EthernetInfo> ethernet;   // Layer 2
  std::optional<IpInfo> ip;               // Layer 3
  std::optional<TcpInfo> tcp;             // Layer 4
  std::optional<UdpInfo> udp;             // Layer 4
};

DissectedPacket Dissect(const PacketView& packet);
```

#### `include/wirepeek/dissector/tcp.h`
```cpp
struct TcpInfo {
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint32_t seq_num = 0;                   // KEY for reassembly
  uint32_t ack_num = 0;
  uint8_t data_offset = 0;                // Header length in 32-bit words
  uint8_t flags = 0;                      // SYN, ACK, FIN, RST, PSH, URG, ECE, CWR
  uint16_t window_size = 0;
  uint16_t checksum = 0;
  uint16_t urgent_pointer = 0;
  uint8_t header_length = 0;
  std::span<const uint8_t> payload;       // Payload after header
};
```

**Flow:** Raw packet → Ethernet → IP → TCP/UDP

---

### 4. **Current Dissection Pipeline (`src/dissector/dissect.cpp`)**

```cpp
DissectedPacket Dissect(const PacketView& packet) {
  // 1. Parse Ethernet (checks EtherType)
  auto eth = ParseEthernet(packet.data);
  if (!eth) return result;
  
  // 2. Only continue for IP
  if (!IPv4 && !IPv6) return result;
  
  // 3. Parse IP layer
  auto ip = ParseIp(eth->payload);
  if (!ip) return result;
  
  // 4. Parse TCP or UDP based on protocol number
  if (protocol == TCP) {
    auto tcp = ParseTcp(ip->payload);
    if (tcp) result.tcp = *tcp;
  } else if (protocol == UDP) {
    auto udp = ParseUdp(ip->payload);
    if (udp) result.udp = *udp;
  }
  
  return result;
}
```

**Key Points:**
- Stops at first failed layer (graceful degradation)
- No error handling—just returns partial results
- All payloads are `std::span<const uint8_t>` (zero-copy)

---

### 5. **Current CLI Usage (`src/cli/main.cpp`)**

```cpp
// Main capture loop
source->Start([&](const PacketView& pkt) {
  auto dissected = wirepeek::dissector::Dissect(pkt);
  auto summary = wirepeek::dissector::FormatSummary(dissected);
  fmt::print("{:%H:%M:%S}.{:06d}  {}\n", tm_val, us.count(), summary);
});
```

**Current Workflow:**
1. Capture packet (PacketView into pcap buffer)
2. Dissect immediately (while data is in buffer)
3. Format and print summary (tcpdump-like output)
4. Discard packet

**Problem for Reassembly:**
- Packets must be processed individually in capture order
- No buffering across packets
- No state between packets

---

### 6. **Build Structure**

#### `CMakeLists.txt` (root)
```cmake
target_link_libraries(wirepeek_lib PUBLIC
  fmt::fmt                    # Formatting
  spdlog::spdlog             # Logging
  Pcap::Pcap                 # Packet capture
  xxhash                     # Hashing (for connection keys)
)
```

#### `src/CMakeLists.txt`
```cmake
add_library(wirepeek_lib STATIC
  dissector/{ethernet,ip,tcp,udp}.cpp
  dissector/dissect.cpp
  capture/{pcap,file}_source.cpp
)

add_executable(wirepeek
  cli/main.cpp
)
target_link_libraries(wirepeek PRIVATE wirepeek_lib CLI11::CLI11)
```

**Dependencies:**
- **fmt** - formatting library
- **spdlog** - logging library
- **CLI11** - CLI argument parsing
- **Pcap** - libpcap (system)
- **xxhash** - fast hashing
- **FTXUI** - TUI framework (not yet used)
- **GoogleTest** - unit testing (tests/CMakeLists.txt)

---

## Phase 2: TCP Stream Reassembly — Design Points

### **What Should Reassembly Do?**

1. **Aggregate TCP segments** from multiple packets into continuous byte streams
2. **Handle reordering** - out-of-order segments
3. **Handle retransmissions** - overlapping segments
4. **Handle packet loss** - gaps (buffering until gap is filled or timeout)
5. **Bidirectional tracking** - client→server and server→client as separate streams
6. **Connection lifecycle** - SYN (open), FIN/RST (close), timeout (auto-close)

### **Where Should It Fit in the Pipeline?**

```
Current: Packet → Dissect → Format & Print

Proposed Phase 2:
┌─────────────────────────────────────────────────────────┐
│ Capture (PacketView)                                    │
└────────────────┬────────────────────────────────────────┘
                 │
                 ↓
            Dissect()
                 │
                 ├─ Extract ConnectionKey from packet
                 ├─ Extract TcpInfo (seq, ack, flags, payload)
                 └─ Create OwnedPacket copy (outlive buffer)
                 │
                 ↓
         ┌─ Stream Reassembler ─┐
         │  (NEW in Phase 2)    │
         │                      │
         │ - ConnectionKey map  │
         │ - Per-stream buffers │
         │ - Reordering logic   │
         │ - Segment assembly   │
         └──────────┬───────────┘
                    │
                    ├─ Emit reassembled "application layer" data
                    └─ Output: (stream_id, data, is_complete)
                    │
                    ↓
            Phase 3: HTTP/gRPC Parser
            (consumes reassembled streams)
```

### **API Shape for Reassembly**

```cpp
// include/wirepeek/reassembler/tcp_reassembler.h
namespace wirepeek::reassembler {

struct StreamData {
  std::vector<uint8_t> bytes;           // Reassembled data
  bool is_complete = false;             // FIN/RST received?
  Timestamp last_packet_time;           // Latest packet timestamp
};

using StreamCallback = std::function<void(
  const ConnectionKey& conn,
  const StreamData& data,
  bool is_final  // Stream closing?
)>;

class TcpReassembler {
 public:
  // Process a single dissected packet
  void ProcessPacket(
    const DissectedPacket& dissected,
    const PacketView& packet  // For timestamp, original_length
  );
  
  // Flush all buffered streams (e.g., on EOF)
  void Flush(StreamCallback callback);
  
  // Get statistics
  struct Stats {
    size_t active_streams = 0;
    uint64_t segments_processed = 0;
    uint64_t segments_reordered = 0;
  };
  Stats GetStats() const;
};

}  // namespace wirepeek::reassembler
```

### **Internal State Per Stream**

```cpp
struct StreamState {
  uint32_t next_seq = 0;                // Expected sequence number
  bool is_client_side = true;           // Direction flag
  std::map<uint32_t, OwnedPacket> buffered_segments;  // Out-of-order
  std::vector<uint8_t> reassembled_data;               // In-order output
  Timestamp creation_time;
  Timestamp last_update_time;
  bool is_complete = false;             // FIN/RST seen?
  
  // Statistics
  uint64_t total_bytes = 0;
  uint64_t reordered_count = 0;
};
```

---

## Summary: Key Insights for Phase 2

### ✅ **What Already Exists**
1. **ConnectionKey** - perfect 5-tuple for stream identification
2. **TcpInfo** - has seq_num, ack_num, flags (all needed for reassembly)
3. **Packet structures** - PacketView (zero-copy) + OwnedPacket (buffering)
4. **Dissection pipeline** - extracts all needed info
5. **Build system** - xxhash dependency already available
6. **CLI structure** - callback-based packet processing

### ❌ **What's Needed for Phase 2**
1. **TcpReassembler class** - stateful stream manager
2. **Stream buffering** - per-stream segment ordering
3. **Segment reordering** - handle out-of-order arrivals
4. **Connection lifecycle** - track SYN/FIN/RST
5. **Output emission** - callback or queue for reassembled data
6. **Timeout handling** - auto-close stale streams
7. **Direction handling** - bidirectional per-flow (not per-direction)

### 📍 **Integration Points**
- **Input:** Dissected TCP packets from `Dissect()`
- **Output:** Reassembled byte streams for Phase 3 (HTTP parser)
- **CLI:** Modify callback in `main.cpp` to use reassembler
- **Files:**
  - New: `include/wirepeek/reassembler/tcp_reassembler.h`
  - New: `src/reassembler/tcp_reassembler.cpp`
  - Modify: `src/CMakeLists.txt` (add reassembler)
  - Modify: `src/cli/main.cpp` (integrate reassembler callback)

### 🎯 **Phase 3 Input Format**
```cpp
// Phase 3 (HTTP parser) will receive:
struct HttpParserInput {
  ConnectionKey conn;                   // Which stream?
  std::span<const uint8_t> reassembled_data;  // In-order bytes
  bool stream_complete;                 // FIN received?
  Timestamp last_activity;
};
```

