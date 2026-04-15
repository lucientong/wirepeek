// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/dissector/ethernet.h>
#include <wirepeek/endian.h>

#include <algorithm>
#include <fmt/format.h>

namespace wirepeek::dissector {

namespace {
// Minimum Ethernet header: 6 (dst) + 6 (src) + 2 (type) = 14 bytes.
constexpr size_t kEthernetHeaderLen = 14;
// 802.1Q VLAN tag adds 4 bytes: 2 (TPID) + 2 (TCI).
constexpr size_t kVlanTagLen = 4;
}  // namespace

DissectResult<EthernetInfo> ParseEthernet(std::span<const uint8_t> data) {
  if (data.size() < kEthernetHeaderLen) {
    return Unexpected<EthernetInfo>(DissectError::kTruncated);
  }

  EthernetInfo info;

  // Parse destination and source MAC addresses.
  std::copy_n(data.data(), 6, info.dst_mac.begin());
  std::copy_n(data.data() + 6, 6, info.src_mac.begin());

  // Read EtherType.
  uint16_t ether_type = ReadU16Be(data.data() + 12);
  size_t header_len = kEthernetHeaderLen;

  // Handle 802.1Q VLAN tagging.
  if (ether_type == ethertype::kVLAN) {
    if (data.size() < kEthernetHeaderLen + kVlanTagLen) {
      return Unexpected<EthernetInfo>(DissectError::kTruncated);
    }
    // TCI: Priority (3 bits) + DEI (1 bit) + VLAN ID (12 bits).
    uint16_t tci = ReadU16Be(data.data() + 14);
    info.vlan_id = tci & 0x0FFF;
    // Real EtherType follows the VLAN tag.
    ether_type = ReadU16Be(data.data() + 16);
    header_len = kEthernetHeaderLen + kVlanTagLen;
  }

  info.ether_type = ether_type;
  info.payload = data.subspan(header_len);

  return info;
}

std::string FormatMac(const MacAddress& mac) {
  return fmt::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3],
                     mac[4], mac[5]);
}

}  // namespace wirepeek::dissector
