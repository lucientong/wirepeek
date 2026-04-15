// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/dissector/udp.h>
#include <wirepeek/endian.h>

namespace wirepeek::dissector {

namespace {
constexpr size_t kUdpHeaderLen = 8;
}  // namespace

DissectResult<UdpInfo> ParseUdp(std::span<const uint8_t> data) {
  if (data.size() < kUdpHeaderLen) {
    return Unexpected<UdpInfo>(DissectError::kTruncated);
  }

  UdpInfo info;
  info.src_port = ReadU16Be(data.data());
  info.dst_port = ReadU16Be(data.data() + 2);
  info.length = ReadU16Be(data.data() + 4);
  info.checksum = ReadU16Be(data.data() + 6);

  // Payload length: use declared length minus header, clamped to available data.
  size_t payload_len = 0;
  if (info.length > kUdpHeaderLen) {
    payload_len =
        std::min(static_cast<size_t>(info.length - kUdpHeaderLen), data.size() - kUdpHeaderLen);
  }
  info.payload = data.subspan(kUdpHeaderLen, payload_len);

  return info;
}

}  // namespace wirepeek::dissector
