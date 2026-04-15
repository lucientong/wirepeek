// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/dissector/dissect.h>
#include <wirepeek/dissector/ethernet.h>
#include <wirepeek/dissector/ip.h>
#include <wirepeek/dissector/tcp.h>
#include <wirepeek/dissector/udp.h>

#include <fmt/format.h>

namespace wirepeek::dissector {

DissectedPacket Dissect(const PacketView& packet) {
  DissectedPacket result;

  // Layer 2: Ethernet.
  auto eth = ParseEthernet(packet.data);
  if (!eth)
    return result;
  result.ethernet = *eth;

  // Only continue for IP packets.
  if (eth->ether_type != ethertype::kIPv4 && eth->ether_type != ethertype::kIPv6) {
    return result;
  }

  // Layer 3: IP.
  auto ip = ParseIp(eth->payload);
  if (!ip)
    return result;
  result.ip = *ip;

  // Layer 4: TCP or UDP.
  if (ip->protocol == ip_protocol::kTCP) {
    auto tcp = ParseTcp(ip->payload);
    if (tcp)
      result.tcp = *tcp;
  } else if (ip->protocol == ip_protocol::kUDP) {
    auto udp = ParseUdp(ip->payload);
    if (udp)
      result.udp = *udp;
  }

  return result;
}

std::string FormatSummary(const DissectedPacket& packet) {
  if (!packet.ip) {
    if (packet.ethernet) {
      return fmt::format("{} -> {} type=0x{:04x}", FormatMac(packet.ethernet->src_mac),
                         FormatMac(packet.ethernet->dst_mac), packet.ethernet->ether_type);
    }
    return "(unparsed)";
  }

  const auto& ip = *packet.ip;
  std::string src_ip = FormatIp(ip.src_ip);
  std::string dst_ip = FormatIp(ip.dst_ip);

  if (packet.tcp) {
    const auto& tcp = *packet.tcp;
    return fmt::format("{}:{} -> {}:{} TCP {} len={}", src_ip, tcp.src_port, dst_ip, tcp.dst_port,
                       FormatTcpFlags(tcp.flags), tcp.payload.size());
  }

  if (packet.udp) {
    const auto& udp = *packet.udp;
    return fmt::format("{}:{} -> {}:{} UDP len={}", src_ip, udp.src_port, dst_ip, udp.dst_port,
                       udp.payload.size());
  }

  return fmt::format("{} -> {} proto={}", src_ip, dst_ip, ip.protocol);
}

}  // namespace wirepeek::dissector
