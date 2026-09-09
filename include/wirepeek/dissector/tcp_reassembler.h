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
#include <list>
#include <map>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

namespace wirepeek::dissector {

enum class StreamEventType : uint8_t {
  kOpen,
  kData,
  kClose,
};

struct StreamEvent {
  const ConnectionKey& key;
  StreamDirection direction;
  StreamEventType type;
  std::span<const uint8_t> data;
  Timestamp timestamp;
  std::optional<std::chrono::microseconds> tcp_handshake;
};

struct ReassemblerConfig {
  size_t max_streams = 10000;
  size_t max_bytes_per_stream = 10 * 1024 * 1024;
  std::chrono::seconds idle_timeout = std::chrono::seconds(30);
};

enum class TcpStreamState : uint8_t {
  kNew,
  kSynSent,
  kEstablished,
  kClosing,
  kClosed,
};

struct BufferedSegment {
  std::vector<uint8_t> data;
  Timestamp timestamp;
};

struct HalfStream {
  uint32_t initial_seq = 0;
  uint32_t next_expected_seq = 0;
  bool seq_initialized = false;
  bool fin_seen = false;
  size_t total_bytes = 0;       ///< Delivered in-order bytes.
  size_t buffered_bytes = 0;    ///< Bytes currently held in out_of_order.
  std::map<uint32_t, BufferedSegment> out_of_order;
};

struct TcpStream {
  ConnectionKey key;
  TcpStreamState state = TcpStreamState::kNew;
  HalfStream halves[2];
  Timestamp last_activity;
  bool client_is_src = true;
  bool in_lru = false;
  std::optional<Timestamp> syn_timestamp;
  std::optional<std::chrono::microseconds> tcp_handshake;
  std::list<ConnectionKey>::iterator lru_it;
};

class TcpReassembler {
 public:
  using StreamCallback = std::function<void(const StreamEvent&)>;

  explicit TcpReassembler(StreamCallback callback, ReassemblerConfig config = {});

  void ProcessPacket(const DissectedPacket& packet, Timestamp ts);
  void FlushExpired(Timestamp now);
  [[nodiscard]] size_t StreamCount() const { return streams_.size(); }

 private:
  TcpStream* GetOrCreateStream(const DissectedPacket& packet, Timestamp ts);
  static ConnectionKey MakeStreamKey(const DissectedPacket& packet);
  int GetDirection(const TcpStream& stream, const DissectedPacket& packet) const;
  void HandleSyn(TcpStream& stream, const DissectedPacket& packet, int dir, Timestamp ts);
  void HandleData(TcpStream& stream, int dir, uint32_t seq, std::span<const uint8_t> payload,
                  Timestamp ts);
  void FlushBuffered(TcpStream& stream, int dir);
  void HandleClose(TcpStream& stream, const DissectedPacket& packet, int dir, Timestamp ts);
  void CloseAndErase(const ConnectionKey& key, int dir, Timestamp ts);
  void TouchLru(TcpStream& stream);
  void Emit(const TcpStream& stream, int dir, StreamEventType type, std::span<const uint8_t> data,
            Timestamp ts);
  static bool SeqBefore(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) < 0; }
  static bool SeqBeforeOrEqual(uint32_t a, uint32_t b) {
    return static_cast<int32_t>(a - b) <= 0;
  }

  std::unordered_map<ConnectionKey, TcpStream> streams_;
  std::list<ConnectionKey> lru_;
  StreamCallback callback_;
  ReassemblerConfig config_;
};

}  // namespace wirepeek::dissector
