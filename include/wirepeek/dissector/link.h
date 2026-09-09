// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file dissector/link.h
/// @brief Non-Ethernet link-layer dissectors (NULL/LOOP/SLL/RAW).

#pragma once

#include <wirepeek/packet.h>
#include <wirepeek/result.h>

#include <cstdint>
#include <span>

namespace wirepeek::dissector {

/// Parsed non-Ethernet link-layer payload pointing at L3.
struct LinkPayload {
  std::span<const uint8_t> payload;  ///< Bytes starting at IP (or next L3) header.
  uint16_t ether_type = 0;           ///< Pseudo EtherType (0x0800 IPv4, 0x86DD IPv6).
};

/// Map a libpcap DLT_* integer to Wirepeek LinkType.
[[nodiscard]] LinkType MapPcapDatalink(int dlt) noexcept;

/// Parse BSD/OpenBSD loopback headers (DLT_NULL / DLT_LOOP).
DissectResult<LinkPayload> ParseNullLoop(std::span<const uint8_t> data, LinkType type) noexcept;

/// Parse Linux cooked capture headers (SLL / SLL2).
DissectResult<LinkPayload> ParseLinuxSll(std::span<const uint8_t> data, LinkType type) noexcept;

/// Parse raw IP packets (DLT_RAW) — entire frame is the IP header.
DissectResult<LinkPayload> ParseRawIp(std::span<const uint8_t> data) noexcept;

}  // namespace wirepeek::dissector
