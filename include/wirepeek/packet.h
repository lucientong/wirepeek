// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file packet.h
/// @brief Packet data structures for zero-copy packet handling.

#pragma once

#include <chrono>
#include <cstdint>
#include <span>
#include <vector>

namespace wirepeek {

/// Microsecond-precision timestamp for packet capture times.
using Timestamp =
    std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds>;

/// Non-owning view into captured packet data.
///
/// This is the hot-path type — used during capture and dissection. It holds a
/// pointer into the pcap ring buffer and must not outlive the buffer.
struct PacketView {
  std::span<const uint8_t> data;  ///< Raw packet bytes (zero-copy into capture buffer).
  Timestamp timestamp;            ///< Capture timestamp.
  uint32_t capture_length = 0;    ///< Number of bytes actually captured.
  uint32_t original_length = 0;   ///< Original packet length on the wire.
};

/// Owning copy of packet data, for async processing or buffering.
///
/// Use this when the packet must outlive the capture buffer (e.g., for queuing
/// to another thread).
struct OwnedPacket {
  std::vector<uint8_t> data;    ///< Owned copy of raw packet bytes.
  Timestamp timestamp;          ///< Capture timestamp.
  uint32_t original_length = 0; ///< Original packet length on the wire.

  /// Construct an OwnedPacket by copying from a PacketView.
  explicit OwnedPacket(const PacketView& view)
      : data(view.data.begin(), view.data.end()),
        timestamp(view.timestamp),
        original_length(view.original_length) {}

  /// Create a non-owning PacketView referencing this packet's data.
  [[nodiscard]] PacketView View() const {
    return PacketView{
        .data = std::span<const uint8_t>(data),
        .timestamp = timestamp,
        .capture_length = static_cast<uint32_t>(data.size()),
        .original_length = original_length,
    };
  }
};

}  // namespace wirepeek
