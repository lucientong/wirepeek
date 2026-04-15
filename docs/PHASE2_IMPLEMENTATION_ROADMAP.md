# Phase 2: TCP Stream Reassembly — Implementation Roadmap

**Status:** Analysis Complete ✅ | Implementation Ready 🚀

---

## Overview

This document outlines the implementation roadmap for Phase 2 (TCP stream reassembly) of wirepeek, with specific file structure, APIs, and integration points.

---

## Implementation Layers

### Layer 1: Core Data Structures (Header File)

**File:** `include/wirepeek/reassembler/tcp_reassembler.h`

```cpp
namespace wirepeek::reassembler {

/// Direction of a stream within a connection.
enum class StreamDirection : uint8_t {
  kClientToServer = 0,
  kServerToClient = 1,
};

/// Configuration for the TCP reassembler.
struct TcpReassemblerConfig {
  size_t max_buffer_per_stream = 10 * 1024 * 1024;   // 10MB
  size_t max_total_buffer = 100 * 1024 * 1024;       // 100MB
  std::chrono::seconds stream_timeout{30};           // Idle timeout
  bool emit_on_psh = true;                           // Emit when PSH flag set
  bool emit_on_fin = true;                           // Emit when FIN flag set
};

/// Reassembled data chunk emitted to the application.
struct ReassembledStream {
  wirepeek::ConnectionKey conn;            // 5-tuple identifier
  std::vector<uint8_t> data;               // In-order, contiguous payload
  wirepeek::Timestamp last_activity;       // Timestamp of last packet
  bool is_complete = false;                // FIN or RST received
  StreamDirection direction;               // Client→Server or Server→Client
};

/// Callback invoked when stream data is available.
using StreamDataCallback = std::function<void(
  const ReassembledStream& stream,
  bool is_final  // Stream is closing?
)>;

/// Main TCP reassembly engine.
class TcpReassembler {
 public:
  explicit TcpReassembler(TcpReassemblerConfig config = {});
  ~TcpReassembler() = default;

  // Non-copyable, movable
  TcpReassembler(const TcpReassembler&) = delete;
  TcpReassembler& operator=(const TcpReassembler&) = delete;
  TcpReassembler(TcpReassembler&&) = default;
  TcpReassembler& operator=(TcpReassembler&&) = default;

  /// Process a single packet (must be TCP from a dissected packet).
  ///
  /// @param dissected The dissected packet (must have tcp field set)
  /// @param packet The original PacketView (for timestamp)
  /// @param callback Called when stream data is ready (may call multiple times)
  void ProcessPacket(
    const dissector::DissectedPacket& dissected,
    const PacketView& packet,
    StreamDataCallback callback
  );

  /// Flush all buffered streams and invoke callback for final data.
  ///
  /// Call this at EOF or when shutting down to emit all pending data.
  /// @param callback Called for each stream being closed
  void Flush(StreamDataCallback callback);

  /// Get statistics about the reassembly process.
  struct Stats {
    size_t active_streams = 0;             // Currently open connections
    uint64_t segments_processed = 0;       // Total segments seen
    uint64_t segments_reordered = 0;       // Out-of-order segments buffered
    uint64_t retransmissions_detected = 0; // Overlapping segments
    uint64_t bytes_reassembled = 0;        // Total bytes in output
  };
  [[nodiscard]] Stats GetStats() const;

  /// Clear all state (for testing or explicit reset).
  void Reset();
};

}  // namespace wirepeek::reassembler
```

---

### Layer 2: Internal State Management (Implementation)

**File:** `src/reassembler/tcp_reassembler.cpp` (sketch)

#### Key Internal Classes:

```cpp
namespace wirepeek::reassembler::detail {

/// Internal state per TCP stream (per direction).
struct PerStreamState {
  // Stream identity
  wirepeek::ConnectionKey conn;
  StreamDirection direction;

  // Sequence tracking
  uint32_t initial_seq = 0;                    // ISN (Initial Seq Number)
  uint32_t next_expected_seq = 0;              // Next seq we expect
  bool syn_seen = false;
  bool fin_seen = false;
  bool rst_seen = false;
  uint32_t fin_seq = 0;                        // Seq number of FIN

  // Data buffering
  std::vector<uint8_t> reassembled_data;       // In-order output
  std::map<uint32_t, std::vector<uint8_t>> buffered_segments;  // Out-of-order

  // Metadata
  wirepeek::Timestamp creation_time;
  wirepeek::Timestamp last_activity_time;

  // Statistics
  uint64_t total_bytes_seen = 0;
  uint64_t reordered_count = 0;
};

/// Helper: Compare sequence numbers with wraparound handling.
inline bool seq_less(uint32_t a, uint32_t b) {
  return static_cast<int32_t>(a - b) < 0;
}

inline bool seq_less_or_equal(uint32_t a, uint32_t b) {
  return static_cast<int32_t>(a - b) <= 0;
}

}  // namespace wirepeek::reassembler::detail
```

#### Algorithm Skeleton:

```cpp
void TcpReassembler::ProcessPacket(
  const dissector::DissectedPacket& dissected,
  const PacketView& packet,
  StreamDataCallback callback
) {
  // Precondition
  assert(dissected.tcp.has_value());
  assert(dissected.ip.has_value());

  const auto& tcp = *dissected.tcp;
  const auto& ip = *dissected.ip;

  // 1. Build ConnectionKey (normalize to canonical form)
  auto conn = BuildConnectionKey(ip, tcp);
  auto direction = DetermineDirection(ip, tcp);  // Client→Server or vice versa

  // 2. Get or create per-stream state
  auto& stream = GetOrCreateStream(conn, direction);

  // 3. Handle SYN (stream initialization)
  if (tcp.flags & dissector::tcp_flags::kSYN) {
    stream.initial_seq = tcp.seq_num;
    stream.next_expected_seq = tcp.seq_num + 1;
    stream.syn_seen = true;
    if (tcp.payload.size() > 0) {
      // Data with SYN is rare but valid
      MaybeAppendSegment(stream, tcp);
    }
    return;
  }

  // 4. Ignore segments before SYN
  if (!stream.syn_seen) return;

  // 5. Handle data payload
  if (tcp.payload.size() > 0) {
    MaybeAppendSegment(stream, tcp);
    TryFlushContiguousData(stream, callback);
  }

  // 6. Handle PSH (application data boundary)
  if ((tcp.flags & dissector::tcp_flags::kPSH) && config_.emit_on_psh) {
    TryFlushContiguousData(stream, callback);
  }

  // 7. Handle FIN (stream close)
  if (tcp.flags & dissector::tcp_flags::kFIN) {
    stream.fin_seen = true;
    stream.fin_seq = tcp.seq_num + tcp.payload.size();
    // Flush remaining data + close
    TryFlushContiguousData(stream, callback);
    if (config_.emit_on_fin) {
      EmitFinalAndClose(stream, callback);
    }
  }

  // 8. Handle RST (abrupt close)
  if (tcp.flags & dissector::tcp_flags::kRST) {
    stream.rst_seen = true;
    EmitFinalAndClose(stream, callback);
  }
}
```

#### Segment Insertion Logic:

```cpp
void MaybeAppendSegment(detail::PerStreamState& stream, const TcpInfo& tcp) {
  uint32_t seg_start = tcp.seq_num;
  uint32_t seg_end = tcp.seq_num + tcp.payload.size();

  // Case 1: Segment ends before next_expected (old/retransmitted)
  if (seq_less(seg_end, stream.next_expected_seq)) {
    stats_.retransmissions_detected++;
    return;  // Ignore
  }

  // Case 2: Segment starts at expected position (in-order)
  if (seg_start == stream.next_expected_seq) {
    stream.reassembled_data.insert(
      stream.reassembled_data.end(),
      tcp.payload.begin(), tcp.payload.end()
    );
    stream.next_expected_seq = seg_end;

    // Try to fill any buffered gaps
    while (!stream.buffered_segments.empty()) {
      auto it = stream.buffered_segments.begin();
      if (it->first == stream.next_expected_seq) {
        auto& data = it->second;
        stream.reassembled_data.insert(
          stream.reassembled_data.end(),
          data.begin(), data.end()
        );
        stream.next_expected_seq += data.size();
        stream.buffered_segments.erase(it);
      } else {
        break;
      }
    }
  }
  // Case 3: Segment starts after expected (reordered/out-of-order)
  else if (seq_less(stream.next_expected_seq, seg_start)) {
    stream.buffered_segments[seg_start].assign(
      tcp.payload.begin(), tcp.payload.end()
    );
    stats_.segments_reordered++;
  }
  // Case 4: Segment overlaps (handled by Case 2 loop or ignored)
}
```

---

### Layer 3: CLI Integration

**File:** `src/cli/main.cpp` (modifications)

```cpp
// Add at top:
#include <wirepeek/reassembler/tcp_reassembler.h>

int main(int argc, char* argv[]) {
  // ... existing arg parsing ...

  // Create reassembler
  wirepeek::reassembler::TcpReassemblerConfig reassembler_config{
    .max_buffer_per_stream = 10 * 1024 * 1024,
    .stream_timeout = std::chrono::seconds(30),
    .emit_on_psh = true,
    .emit_on_fin = true,
  };
  auto reassembler = wirepeek::reassembler::TcpReassembler(reassembler_config);

  // Capture loop
  source->Start([&](const wirepeek::PacketView& pkt) {
    if (!g_running) {
      source->Stop();
      return;
    }

    auto dissected = wirepeek::dissector::Dissect(pkt);

    // Only process TCP packets
    if (!dissected.tcp || !dissected.ip) {
      // For non-TCP, still print as before
      auto summary = wirepeek::dissector::FormatSummary(dissected);
      fmt::print("[non-TCP] {}\n", summary);
      return;
    }

    // Process TCP with reassembler
    reassembler.ProcessPacket(
      dissected,
      pkt,
      [&](const wirepeek::reassembler::ReassembledStream& stream, bool is_final) {
        // Output reassembled stream data
        fmt::print(
          "[TCP STREAM] {}:{} -> {}:{} (dir={}) {} bytes%s\n",
          FormatIp(stream.conn.src_ip),
          stream.conn.src_port,
          FormatIp(stream.conn.dst_ip),
          stream.conn.dst_port,
          static_cast<int>(stream.direction),
          stream.data.size(),
          is_final ? " [FINAL]" : ""
        );

        // Option: dump hex
        if (verbose) {
          fmt::print("Data: {}\n", fmt::join(stream.data, " "));
        }
      }
    );

    ++packet_count;
    if (count > 0 && packet_count >= static_cast<uint64_t>(count)) {
      source->Stop();
    }
  });

  // Flush remaining streams
  reassembler.Flush([](const wirepeek::reassembler::ReassembledStream& stream, bool _) {
    fmt::print("[TCP STREAM] (flushed) {} bytes\n", stream.data.size());
  });

  // Print stats
  auto stats = reassembler.GetStats();
  fmt::print(stderr, "--- TCP Reassembly Stats ---\n");
  fmt::print(stderr, "Active streams: {}\n", stats.active_streams);
  fmt::print(stderr, "Segments processed: {}\n", stats.segments_processed);
  fmt::print(stderr, "Reordered: {}\n", stats.segments_reordered);
  fmt::print(stderr, "Retransmissions: {}\n", stats.retransmissions_detected);
  fmt::print(stderr, "Bytes reassembled: {}\n", stats.bytes_reassembled);

  // ... rest of main ...
}
```

---

### Layer 4: Build System

**File:** `src/CMakeLists.txt` (modifications)

```cmake
add_library(wirepeek_lib STATIC
  dissector/ethernet.cpp
  dissector/ip.cpp
  dissector/tcp.cpp
  dissector/udp.cpp
  dissector/dissect.cpp
  capture/pcap_source.cpp
  capture/file_source.cpp
  reassembler/tcp_reassembler.cpp       # ADD THIS LINE
)
```

---

## Implementation Checklist

### Phase 2a: Foundation (Minimal MVP)
- [ ] Create `include/wirepeek/reassembler/tcp_reassembler.h` header
- [ ] Define `TcpReassembler` class with basic API
- [ ] Create `src/reassembler/tcp_reassembler.cpp` implementation
- [ ] Implement basic segment buffering (no reordering)
- [ ] Implement in-order segment assembly
- [ ] Handle SYN/FIN/RST flags
- [ ] Update `src/CMakeLists.txt` to build reassembler

### Phase 2b: Integration (CLI)
- [ ] Integrate `TcpReassembler` into capture loop
- [ ] Add callback for reassembled data output
- [ ] Test with pcap file containing multiple TCP flows
- [ ] Verify packet-level dissection still works
- [ ] Add `--reassemble` flag to enable/disable

### Phase 2c: Advanced Features
- [ ] Implement sequence number wraparound handling
- [ ] Handle out-of-order segment buffering
- [ ] Implement timeout-based stream closure
- [ ] Detect and skip retransmissions
- [ ] Add configurable buffer limits (memory DoS protection)

### Phase 2d: Testing & Metrics
- [ ] Write unit tests for segment insertion logic
- [ ] Test with reordered packet captures
- [ ] Test with packet loss scenarios
- [ ] Benchmark reassembly throughput
- [ ] Measure memory usage under load

### Phase 2e: Documentation
- [ ] Document API in header comments
- [ ] Add examples in README
- [ ] Create test fixtures (sample pcap files)
- [ ] Document configuration options

---

## Data Flow Summary

```
Capture Loop:
  PacketView → Dissect() → DissectedPacket
                             ↓
                    TcpReassembler::ProcessPacket()
                             ↓
                       StreamDataCallback
                             ↓
                       CLI Output / Buffering
                             ↓
                    (Ready for Phase 3: HTTP parser)
```

---

## Testing Strategy

### Unit Tests
- Sequence number comparison (wraparound)
- Segment insertion (in-order, out-of-order, overlapping)
- Buffer limit enforcement
- Stream state transitions

### Integration Tests
- Single continuous stream
- Reordered packets
- Retransmitted segments
- Multiple simultaneous streams
- Stream close (FIN, RST)
- Timeout handling

### Performance Tests
- Throughput (Mbps)
- Memory per stream
- Latency (packet to reassembled output)

---

## Known Limitations & Future Work

1. **No IPv6 support yet** (infrastructure exists, needs testing)
2. **No SACK support** (selective ACK optimization)
3. **No urgent pointer handling** (URG flag)
4. **No connection pooling** (all streams kept in memory until timeout)
5. **No multi-threaded reassembly** (Phase 4 with TUI)
6. **No custom TCP options parsing** (MSS, window scale, timestamps)

---

## Success Criteria

- ✅ Reassembler passes unit tests
- ✅ Handles 95%+ of real-world packet captures correctly
- ✅ Memory usage stays within configured limits
- ✅ No crashes or undefined behavior on malformed input
- ✅ CLI integration works seamlessly
- ✅ Output is ready for Phase 3 (HTTP parser)

