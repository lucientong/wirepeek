// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file stream.h
/// @brief TCP stream structures (Phase 2: stream reassembly).

#pragma once

#include <array>
#include <cstdint>
#include <functional>

namespace wirepeek {

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
    // Simple FNV-1a hash over the raw bytes of the key.
    size_t h = 14695981039346656037ULL;
    auto hash_bytes = [&h](const void* data, size_t len) {
      const auto* p = static_cast<const uint8_t*>(data);
      for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
      }
    };
    hash_bytes(key.src_ip.data(), key.src_ip.size());
    hash_bytes(key.dst_ip.data(), key.dst_ip.size());
    hash_bytes(&key.src_port, sizeof(key.src_port));
    hash_bytes(&key.dst_port, sizeof(key.dst_port));
    hash_bytes(&key.protocol, sizeof(key.protocol));
    return h;
  }
};
