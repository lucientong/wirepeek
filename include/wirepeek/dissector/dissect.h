// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file dissector/dissect.h
/// @brief Full packet dissection pipeline.

#pragma once

#include <wirepeek/dissector/ethernet.h>
#include <wirepeek/dissector/ip.h>
#include <wirepeek/dissector/tcp.h>
#include <wirepeek/dissector/udp.h>
#include <wirepeek/packet.h>

#include <optional>
#include <string>

namespace wirepeek::dissector {

/// Fully dissected packet containing all parsed protocol layers.
struct DissectedPacket {
  std::optional<EthernetInfo> ethernet;  ///< Layer 2 — Ethernet.
  std::optional<IpInfo> ip;              ///< Layer 3 — IP.
  std::optional<TcpInfo> tcp;            ///< Layer 4 — TCP.
  std::optional<UdpInfo> udp;            ///< Layer 4 — UDP.
};

/// Dissect a raw captured packet through all protocol layers.
///
/// Chains: Ethernet → IP → TCP/UDP. Stops at the first unsupported layer
/// rather than returning an error, so partial results are available.
///
/// @param packet The captured packet view.
/// @return A DissectedPacket with all successfully parsed layers populated.
DissectedPacket Dissect(const PacketView& packet);

/// Format a one-line summary of a dissected packet (similar to tcpdump output).
///
/// Example: "192.168.1.1:443 → 10.0.0.1:54321 TCP [SYN, ACK] len=0"
std::string FormatSummary(const DissectedPacket& packet);

}  // namespace wirepeek::dissector
