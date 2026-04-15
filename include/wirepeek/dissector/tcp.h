// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file dissector/tcp.h
/// @brief TCP header dissector.

#pragma once

#include <cstdint>
#include <span>

#include <wirepeek/result.h>

namespace wirepeek::dissector {

/// TCP flag bitmask values.
namespace tcp_flags {
inline constexpr uint8_t kFIN = 0x01;
inline constexpr uint8_t kSYN = 0x02;
inline constexpr uint8_t kRST = 0x04;
inline constexpr uint8_t kPSH = 0x08;
inline constexpr uint8_t kACK = 0x10;
inline constexpr uint8_t kURG = 0x20;
inline constexpr uint8_t kECE = 0x40;
inline constexpr uint8_t kCWR = 0x80;
}  // namespace tcp_flags

/// Parsed TCP header information.
struct TcpInfo {
  uint16_t src_port = 0;              ///< Source port.
  uint16_t dst_port = 0;              ///< Destination port.
  uint32_t seq_num = 0;               ///< Sequence number.
  uint32_t ack_num = 0;               ///< Acknowledgement number.
  uint8_t data_offset = 0;            ///< Header length in 32-bit words.
  uint8_t flags = 0;                  ///< TCP flags bitmask.
  uint16_t window_size = 0;           ///< Window size.
  uint16_t checksum = 0;              ///< TCP checksum.
  uint16_t urgent_pointer = 0;        ///< Urgent pointer.
  uint8_t header_length = 0;          ///< Header length in bytes (data_offset * 4).
  std::span<const uint8_t> payload;   ///< Payload after TCP header.
};

/// Parse a TCP header.
///
/// @param data Raw bytes starting from the TCP header.
/// @return Parsed TcpInfo or a DissectError.
DissectResult<TcpInfo> ParseTcp(std::span<const uint8_t> data);

/// Format TCP flags as a human-readable string (e.g., "[SYN, ACK]").
std::string FormatTcpFlags(uint8_t flags);

}  // namespace wirepeek::dissector
