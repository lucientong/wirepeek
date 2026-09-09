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
using Timestamp = std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds>;

/// Link-layer type, matching libpcap DLT_* values we support.
enum class LinkType : uint32_t {
  kNull = 0,       ///< BSD loopback (DLT_NULL).
  kEthernet = 1,   ///< Ethernet (DLT_EN10MB).
  kRaw = 12,       ///< Raw IP (DLT_RAW).
  kLoop = 108,     ///< OpenBSD loopback (DLT_LOOP).
  kLinuxSll = 113, ///< Linux cooked capture v1 (DLT_LINUX_SLL).
  kLinuxSll2 = 276,///< Linux cooked capture v2 (DLT_LINUX_SLL2).
  kUnknown = 0xFFFFFFFFu,
};

/// Non-owning view into captured packet data.
///
/// This is the hot-path type — used during capture and dissection. It holds a
/// pointer into the pcap ring buffer and must not outlive the buffer.
struct PacketView {
  std::span<const uint8_t> data;  ///< Raw packet bytes (zero-copy into capture buffer).
  Timestamp timestamp;            ///< Capture timestamp.
  uint32_t capture_length = 0;    ///< Number of bytes actually captured.
  uint32_t original_length = 0;   ///< Original packet length on the wire.
  LinkType link_type = LinkType::kEthernet;  ///< Link-layer encapsulation.
};

/// Owning copy of packet data, for async processing or buffering.
///
/// Use this when the packet must outlive the capture buffer (e.g., for queuing
/// to another thread).
struct OwnedPacket {
  std::vector<uint8_t> data;     ///< Owned copy of raw packet bytes.
  Timestamp timestamp;           ///< Capture timestamp.
  uint32_t original_length = 0;  ///< Original packet length on the wire.
  LinkType link_type = LinkType::kEthernet;

  /// Construct an OwnedPacket by copying from a PacketView.
  explicit OwnedPacket(const PacketView& view)
      : data(view.data.begin(), view.data.end()),
        timestamp(view.timestamp),
        original_length(view.original_length),
        link_type(view.link_type) {}

  /// Create a non-owning PacketView referencing this packet's data.
  [[nodiscard]] PacketView View() const {
    return PacketView{
        .data = std::span<const uint8_t>(data),
        .timestamp = timestamp,
        .capture_length = static_cast<uint32_t>(data.size()),
        .original_length = original_length,
        .link_type = link_type,
    };
  }
};

}  // namespace wirepeek
