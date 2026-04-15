// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file dissector/tcp_reassembler.h
/// @brief TCP stream reassembly — collects segments, reorders, delivers in-order bytes.

#pragma once

#include <wirepeek/dissector/dissect.h>
#include <wirepeek/packet.h>
#include <wirepeek/stream.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <span>
#include <unordered_map>
#include <vector>

namespace wirepeek::dissector {

/// Event types emitted by the TCP reassembler.
enum class StreamEventType : uint8_t {
  kOpen,   ///< New stream opened (SYN or first data).
  kData,   ///< In-order data available.
  kClose,  ///< Stream closed (FIN/RST/timeout).
};

/// Event payload delivered via callback.
struct StreamEvent {
  const ConnectionKey& key;       ///< Stream identifier.
  StreamDirection direction;      ///< Which direction this event is for.
  StreamEventType type;           ///< Event type.
  std::span<const uint8_t> data;  ///< Newly available in-order bytes (empty for open/close).
};

/// Configuration for the TCP reassembler.
struct ReassemblerConfig {
  size_t max_streams = 1000;                                     ///< Max concurrent streams.
  size_t max_bytes_per_stream = 10 * 1024 * 1024;                ///< 10MB per stream.
  std::chrono::seconds idle_timeout = std::chrono::seconds(30);  ///< Idle stream timeout.
};

/// TCP connection state.
enum class TcpStreamState : uint8_t {
  kNew,          ///< Just created, no SYN seen yet (mid-flow join).
  kSynSent,      ///< SYN seen, waiting for SYN-ACK.
  kEstablished,  ///< Connection established (data can flow).
  kClosing,      ///< FIN seen from at least one side.
  kClosed,       ///< Both sides closed or RST received.
};

/// Per-direction stream data.
struct HalfStream {
  uint32_t initial_seq = 0;        ///< Initial sequence number (from SYN or first data).
  uint32_t next_expected_seq = 0;  ///< Next expected sequence number.
  bool seq_initialized = false;    ///< Whether initial_seq has been set.
  bool fin_seen = false;           ///< FIN received.
  size_t total_bytes = 0;          ///< Total reassembled bytes.
  std::map<uint32_t, std::vector<uint8_t>> out_of_order;  ///< Buffered out-of-order segments.
};

/// State for a single TCP connection (both directions).
struct TcpStream {
  ConnectionKey key;
  TcpStreamState state = TcpStreamState::kNew;
  HalfStream halves[2];       ///< [0] = client→server, [1] = server→client.
  Timestamp last_activity;    ///< Last packet timestamp.
  bool client_is_src = true;  ///< If true, key.src is the client (SYN sender).
};

/// TCP stream reassembler.
///
/// Tracks TCP connections, reorders out-of-order segments, and delivers
/// contiguous byte streams via a callback. This is the bridge between
/// raw packet dissection (Phase 1) and application-layer parsing (Phase 3).
class TcpReassembler {
 public:
  using StreamCallback = std::function<void(const StreamEvent&)>;

  /// Create a reassembler with the given callback and configuration.
  explicit TcpReassembler(StreamCallback callback, ReassemblerConfig config = {});

  /// Process a dissected packet. Non-TCP packets are silently ignored.
  void ProcessPacket(const DissectedPacket& packet, Timestamp ts);

  /// Flush and remove streams that have been idle longer than the configured timeout.
  void FlushExpired(Timestamp now);

  /// Number of currently tracked streams.
  [[nodiscard]] size_t StreamCount() const { return streams_.size(); }

 private:
  /// Get or create the stream for a packet. Returns nullptr if max_streams exceeded.
  TcpStream* GetOrCreateStream(const DissectedPacket& packet, Timestamp ts);

  /// Build a normalized ConnectionKey (lower IP:port as src for consistency).
  static ConnectionKey MakeStreamKey(const DissectedPacket& packet);

  /// Determine which half-stream direction this packet belongs to.
  int GetDirection(const TcpStream& stream, const DissectedPacket& packet) const;

  /// Handle SYN flag.
  void HandleSyn(TcpStream& stream, const DissectedPacket& packet, int dir);

  /// Handle data payload.
  void HandleData(TcpStream& stream, int dir, uint32_t seq, std::span<const uint8_t> payload);

  /// Try to flush contiguous buffered segments.
  void FlushBuffered(TcpStream& stream, int dir);

  /// Handle FIN/RST flags.
  void HandleClose(TcpStream& stream, const DissectedPacket& packet, int dir);

  /// Emit a stream event via the callback.
  void Emit(const TcpStream& stream, int dir, StreamEventType type,
            std::span<const uint8_t> data = {});

  /// Sequence number comparison (handles 32-bit wraparound).
  static bool SeqBefore(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) < 0; }

  std::unordered_map<ConnectionKey, TcpStream> streams_;
  StreamCallback callback_;
  ReassemblerConfig config_;
};

}  // namespace wirepeek::dissector
