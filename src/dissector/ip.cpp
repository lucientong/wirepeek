// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/dissector/ip.h>

#include <wirepeek/endian.h>

#include <fmt/format.h>

namespace wirepeek::dissector {

namespace {
constexpr size_t kIpv4MinHeaderLen = 20;
constexpr size_t kIpv6HeaderLen = 40;
}  // namespace

static DissectResult<IpInfo> ParseIpv4(std::span<const uint8_t> data) {
  if (data.size() < kIpv4MinHeaderLen) {
    return Unexpected<IpInfo>(DissectError::kTruncated);
  }

  uint8_t version_ihl = data[0];
  uint8_t version = (version_ihl >> 4) & 0x0F;
  if (version != 4) {
    return Unexpected<IpInfo>(DissectError::kUnsupportedVersion);
  }

  uint8_t ihl = version_ihl & 0x0F;
  if (ihl < 5) {
    return Unexpected<IpInfo>(DissectError::kInvalidHeader);
  }

  uint8_t header_len = ihl * 4;
  if (data.size() < header_len) {
    return Unexpected<IpInfo>(DissectError::kTruncated);
  }

  IpInfo info;
  info.version = 4;
  info.header_length = header_len;
  info.total_length = ReadU16Be(data.data() + 2);
  info.ttl = data[8];
  info.protocol = data[9];

  Ipv4Address src, dst;
  std::copy_n(data.data() + 12, 4, src.begin());
  std::copy_n(data.data() + 16, 4, dst.begin());
  info.src_ip = src;
  info.dst_ip = dst;

  // Payload starts after the IP header.
  // Use the minimum of total_length and available data to handle truncated captures.
  size_t payload_offset = header_len;
  size_t payload_len = std::min(static_cast<size_t>(info.total_length) - header_len,
                                data.size() - payload_offset);
  info.payload = data.subspan(payload_offset, payload_len);

  return info;
}

static DissectResult<IpInfo> ParseIpv6(std::span<const uint8_t> data) {
  if (data.size() < kIpv6HeaderLen) {
    return Unexpected<IpInfo>(DissectError::kTruncated);
  }

  uint8_t version = (data[0] >> 4) & 0x0F;
  if (version != 6) {
    return Unexpected<IpInfo>(DissectError::kUnsupportedVersion);
  }

  IpInfo info;
  info.version = 6;
  info.header_length = kIpv6HeaderLen;

  // Payload length (does not include the 40-byte fixed header).
  uint16_t payload_length = ReadU16Be(data.data() + 4);
  info.total_length = kIpv6HeaderLen + payload_length;
  info.protocol = data[6];  // Next Header.
  info.ttl = data[7];       // Hop Limit.

  Ipv6Address src, dst;
  std::copy_n(data.data() + 8, 16, src.begin());
  std::copy_n(data.data() + 24, 16, dst.begin());
  info.src_ip = src;
  info.dst_ip = dst;

  size_t available_payload = std::min(static_cast<size_t>(payload_length),
                                      data.size() - kIpv6HeaderLen);
  info.payload = data.subspan(kIpv6HeaderLen, available_payload);

  return info;
}

DissectResult<IpInfo> ParseIp(std::span<const uint8_t> data) {
  if (data.empty()) {
    return Unexpected<IpInfo>(DissectError::kTruncated);
  }

  uint8_t version = (data[0] >> 4) & 0x0F;
  switch (version) {
    case 4:
      return ParseIpv4(data);
    case 6:
      return ParseIpv6(data);
    default:
      return Unexpected<IpInfo>(DissectError::kUnsupportedVersion);
  }
}

std::string FormatIp(const IpAddress& addr) {
  if (const auto* v4 = std::get_if<Ipv4Address>(&addr)) {
    return fmt::format("{}.{}.{}.{}", (*v4)[0], (*v4)[1], (*v4)[2], (*v4)[3]);
  }

  const auto& v6 = std::get<Ipv6Address>(addr);
  // Simplified IPv6 formatting: full hex groups separated by colons.
  return fmt::format("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:"
                     "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                     v6[0], v6[1], v6[2], v6[3], v6[4], v6[5], v6[6], v6[7],
                     v6[8], v6[9], v6[10], v6[11], v6[12], v6[13], v6[14], v6[15]);
}

}  // namespace wirepeek::dissector
