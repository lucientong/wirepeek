// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file dissector/ip.h
/// @brief IPv4 and IPv6 header dissector.

#pragma once

#include <wirepeek/result.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <variant>

namespace wirepeek::dissector {

/// IP protocol numbers.
namespace ip_protocol {
inline constexpr uint8_t kICMP = 1;
inline constexpr uint8_t kTCP = 6;
inline constexpr uint8_t kUDP = 17;
inline constexpr uint8_t kICMPv6 = 58;
}  // namespace ip_protocol

/// IPv4 address (4 bytes).
using Ipv4Address = std::array<uint8_t, 4>;

/// IPv6 address (16 bytes).
using Ipv6Address = std::array<uint8_t, 16>;

/// IP address — either IPv4 or IPv6.
using IpAddress = std::variant<Ipv4Address, Ipv6Address>;

/// Parsed IP header information.
struct IpInfo {
  uint8_t version = 0;               ///< IP version (4 or 6).
  IpAddress src_ip;                  ///< Source IP address.
  IpAddress dst_ip;                  ///< Destination IP address.
  uint8_t protocol = 0;              ///< Next-layer protocol (TCP=6, UDP=17, etc.).
  uint8_t ttl = 0;                   ///< Time-to-live (IPv4) / Hop limit (IPv6).
  uint16_t total_length = 0;         ///< Total IP packet length.
  uint8_t header_length = 0;         ///< IP header length in bytes.
  std::span<const uint8_t> payload;  ///< Payload after IP header.
};

/// Parse an IP header (auto-detects IPv4 vs IPv6).
///
/// @param data Raw bytes starting from the IP header.
/// @return Parsed IpInfo or a DissectError.
DissectResult<IpInfo> ParseIp(std::span<const uint8_t> data);

/// Format an IP address as a human-readable string.
/// IPv4: "a.b.c.d", IPv6: abbreviated hex notation.
std::string FormatIp(const IpAddress& addr);

}  // namespace wirepeek::dissector
