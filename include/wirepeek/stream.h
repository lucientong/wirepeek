// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file stream.h
/// @brief TCP stream structures (Phase 2: stream reassembly).

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <xxhash.h>

namespace wirepeek {

/// Direction of data within a TCP stream.
enum class StreamDirection : uint8_t {
  kClientToServer = 0,  ///< Client (SYN initiator) → Server.
  kServerToClient = 1,  ///< Server → Client.
};

/// 5-tuple connection key for TCP/UDP flow identification.
struct ConnectionKey {
  std::array<uint8_t, 16> src_ip{};  ///< Source IP (4 bytes for IPv4, 16 for IPv6).
  std::array<uint8_t, 16> dst_ip{};  ///< Destination IP.
  uint16_t src_port = 0;             ///< Source port.
  uint16_t dst_port = 0;             ///< Destination port.
  uint8_t ip_version = 4;            ///< IP version (4 or 6).
  uint8_t protocol = 0;              ///< IP protocol number (6=TCP, 17=UDP).

  bool operator==(const ConnectionKey& other) const = default;
};

}  // namespace wirepeek

/// Hash specialization for ConnectionKey, used in connection tables.
template <>
struct std::hash<wirepeek::ConnectionKey> {
  size_t operator()(const wirepeek::ConnectionKey& key) const noexcept {
    std::array<uint8_t, 38> bytes{};
    std::copy(key.src_ip.begin(), key.src_ip.end(), bytes.begin());
    std::copy(key.dst_ip.begin(), key.dst_ip.end(), bytes.begin() + 16);
    bytes[32] = static_cast<uint8_t>(key.src_port >> 8);
    bytes[33] = static_cast<uint8_t>(key.src_port);
    bytes[34] = static_cast<uint8_t>(key.dst_port >> 8);
    bytes[35] = static_cast<uint8_t>(key.dst_port);
    bytes[36] = key.ip_version;
    bytes[37] = key.protocol;
    return static_cast<size_t>(XXH3_64bits(bytes.data(), bytes.size()));
  }
};
