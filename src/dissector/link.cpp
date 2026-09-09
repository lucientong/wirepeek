// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/dissector/ethernet.h>
#include <wirepeek/dissector/link.h>
#include <wirepeek/endian.h>

#ifndef DLT_NULL
#define DLT_NULL 0
#endif
#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif
#ifndef DLT_RAW
#define DLT_RAW 12
#endif
#ifndef DLT_LOOP
#define DLT_LOOP 108
#endif
#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif
#ifndef DLT_LINUX_SLL2
#define DLT_LINUX_SLL2 276
#endif

namespace wirepeek::dissector {

LinkType MapPcapDatalink(int dlt) noexcept {
  switch (dlt) {
    case DLT_NULL:
      return LinkType::kNull;
    case DLT_EN10MB:
      return LinkType::kEthernet;
    case DLT_RAW:
      return LinkType::kRaw;
    case DLT_LOOP:
      return LinkType::kLoop;
    case DLT_LINUX_SLL:
      return LinkType::kLinuxSll;
    case DLT_LINUX_SLL2:
      return LinkType::kLinuxSll2;
    default:
      return LinkType::kUnknown;
  }
}

DissectResult<LinkPayload> ParseNullLoop(std::span<const uint8_t> data, LinkType type) noexcept {
  if (data.size() < 4) {
    return Unexpected<LinkPayload>(DissectError::kTruncated);
  }

  uint32_t family = 0;
  if (type == LinkType::kLoop) {
    family = ReadU32Be(data.data());
  } else {
    // DLT_NULL: host byte order on the capturing machine. Try both.
    family = static_cast<uint32_t>(data[0]) | (static_cast<uint32_t>(data[1]) << 8) |
             (static_cast<uint32_t>(data[2]) << 16) | (static_cast<uint32_t>(data[3]) << 24);
    if (family != 2 && family != 24 && family != 28 && family != 30) {
      family = ReadU32Be(data.data());
    }
  }

  uint16_t ether_type = 0;
  // AF_INET = 2; AF_INET6 varies (24/28/30).
  if (family == 2) {
    ether_type = ethertype::kIPv4;
  } else if (family == 24 || family == 28 || family == 30) {
    ether_type = ethertype::kIPv6;
  } else {
    return Unexpected<LinkPayload>(DissectError::kUnsupportedVersion);
  }

  return LinkPayload{.payload = data.subspan(4), .ether_type = ether_type};
}

DissectResult<LinkPayload> ParseLinuxSll(std::span<const uint8_t> data, LinkType type) noexcept {
  if (type == LinkType::kLinuxSll2) {
    // SLL2: protocol(2) + reserved(2) + ifindex(4) + hatype(2) + pkttype(1) +
    // halen(1) + addr(8) = 20 bytes. Protocol is at offset 0 (big-endian).
    if (data.size() < 20) {
      return Unexpected<LinkPayload>(DissectError::kTruncated);
    }
    return LinkPayload{.payload = data.subspan(20), .ether_type = ReadU16Be(data.data())};
  }

  // SLL: pkttype(2) + hatype(2) + halen(2) + addr(8) + protocol(2) = 16 bytes.
  if (data.size() < 16) {
    return Unexpected<LinkPayload>(DissectError::kTruncated);
  }
  return LinkPayload{.payload = data.subspan(16), .ether_type = ReadU16Be(data.data() + 14)};
}

DissectResult<LinkPayload> ParseRawIp(std::span<const uint8_t> data) noexcept {
  if (data.empty()) {
    return Unexpected<LinkPayload>(DissectError::kTruncated);
  }
  const uint8_t version = (data[0] >> 4) & 0x0F;
  if (version == 4) {
    return LinkPayload{.payload = data, .ether_type = ethertype::kIPv4};
  }
  if (version == 6) {
    return LinkPayload{.payload = data, .ether_type = ethertype::kIPv6};
  }
  return Unexpected<LinkPayload>(DissectError::kUnsupportedVersion);
}

}  // namespace wirepeek::dissector
