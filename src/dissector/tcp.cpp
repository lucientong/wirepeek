// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/dissector/tcp.h>

#include <wirepeek/endian.h>

#include <fmt/format.h>

#include <string>
#include <vector>

namespace wirepeek::dissector {

namespace {
constexpr size_t kTcpMinHeaderLen = 20;
}  // namespace

DissectResult<TcpInfo> ParseTcp(std::span<const uint8_t> data) {
  if (data.size() < kTcpMinHeaderLen) {
    return Unexpected<TcpInfo>(DissectError::kTruncated);
  }

  TcpInfo info;
  info.src_port = ReadU16Be(data.data());
  info.dst_port = ReadU16Be(data.data() + 2);
  info.seq_num = ReadU32Be(data.data() + 4);
  info.ack_num = ReadU32Be(data.data() + 8);

  // Data offset is the upper 4 bits of byte 12, in 32-bit words.
  info.data_offset = (data[12] >> 4) & 0x0F;
  info.header_length = info.data_offset * 4;

  if (info.header_length < kTcpMinHeaderLen) {
    return Unexpected<TcpInfo>(DissectError::kInvalidHeader);
  }
  if (data.size() < info.header_length) {
    return Unexpected<TcpInfo>(DissectError::kTruncated);
  }

  info.flags = data[13];
  info.window_size = ReadU16Be(data.data() + 14);
  info.checksum = ReadU16Be(data.data() + 16);
  info.urgent_pointer = ReadU16Be(data.data() + 18);

  info.payload = data.subspan(info.header_length);

  return info;
}

std::string FormatTcpFlags(uint8_t flags) {
  std::vector<std::string_view> names;
  if (flags & tcp_flags::kSYN) names.push_back("SYN");
  if (flags & tcp_flags::kACK) names.push_back("ACK");
  if (flags & tcp_flags::kFIN) names.push_back("FIN");
  if (flags & tcp_flags::kRST) names.push_back("RST");
  if (flags & tcp_flags::kPSH) names.push_back("PSH");
  if (flags & tcp_flags::kURG) names.push_back("URG");
  if (flags & tcp_flags::kECE) names.push_back("ECE");
  if (flags & tcp_flags::kCWR) names.push_back("CWR");

  if (names.empty()) return "[]";
  return fmt::format("[{}]", fmt::join(names, ", "));
}

}  // namespace wirepeek::dissector
