// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file dissector/udp.h
/// @brief UDP header dissector.

#pragma once

#include <wirepeek/result.h>

#include <cstdint>
#include <span>

namespace wirepeek::dissector {

/// Parsed UDP header information.
struct UdpInfo {
  uint16_t src_port = 0;             ///< Source port.
  uint16_t dst_port = 0;             ///< Destination port.
  uint16_t length = 0;               ///< Total UDP datagram length (header + payload).
  uint16_t checksum = 0;             ///< UDP checksum.
  std::span<const uint8_t> payload;  ///< Payload after UDP header.
};

/// Parse a UDP header.
///
/// @param data Raw bytes starting from the UDP header.
/// @return Parsed UdpInfo or a DissectError.
DissectResult<UdpInfo> ParseUdp(std::span<const uint8_t> data);

}  // namespace wirepeek::dissector
