// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file dissector/ethernet.h
/// @brief Ethernet II frame dissector.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

#include <wirepeek/result.h>

namespace wirepeek::dissector {

/// MAC address type (6 bytes).
using MacAddress = std::array<uint8_t, 6>;

/// Common EtherType values.
namespace ethertype {
inline constexpr uint16_t kIPv4 = 0x0800;
inline constexpr uint16_t kIPv6 = 0x86DD;
inline constexpr uint16_t kARP = 0x0806;
inline constexpr uint16_t kVLAN = 0x8100;
}  // namespace ethertype

/// Parsed Ethernet II frame information.
struct EthernetInfo {
  MacAddress src_mac{};                ///< Source MAC address.
  MacAddress dst_mac{};                ///< Destination MAC address.
  uint16_t ether_type = 0;            ///< EtherType (after VLAN stripping if present).
  std::optional<uint16_t> vlan_id;    ///< VLAN ID if 802.1Q tagged.
  std::span<const uint8_t> payload;   ///< Payload after Ethernet header.
};

/// Parse an Ethernet II frame.
///
/// Handles standard Ethernet II and single 802.1Q VLAN tags.
/// @param data Raw frame bytes starting from the Ethernet header.
/// @return Parsed EthernetInfo or a DissectError.
DissectResult<EthernetInfo> ParseEthernet(std::span<const uint8_t> data);

/// Format a MAC address as "xx:xx:xx:xx:xx:xx".
std::string FormatMac(const MacAddress& mac);

}  // namespace wirepeek::dissector
