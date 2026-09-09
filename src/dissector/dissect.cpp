// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/dissector/dissect.h>
#include <wirepeek/dissector/ethernet.h>
#include <wirepeek/dissector/ip.h>
#include <wirepeek/dissector/link.h>
#include <wirepeek/dissector/tcp.h>
#include <wirepeek/dissector/udp.h>

#include <fmt/format.h>

namespace wirepeek::dissector {

namespace {

void DissectTransport(DissectedPacket& result, const IpInfo& ip) {
  if (ip.protocol == ip_protocol::kTCP) {
    auto tcp = ParseTcp(ip.payload);
    if (tcp)
      result.tcp = *tcp;
  } else if (ip.protocol == ip_protocol::kUDP) {
    auto udp = ParseUdp(ip.payload);
    if (udp)
      result.udp = *udp;
  }
}

void DissectFromIp(DissectedPacket& result, std::span<const uint8_t> ip_bytes) {
  auto ip = ParseIp(ip_bytes);
  if (!ip)
    return;
  result.ip = *ip;
  DissectTransport(result, *ip);
}

}  // namespace

DissectedPacket Dissect(const PacketView& packet) {
  DissectedPacket result;
  result.link_type = packet.link_type;

  switch (packet.link_type) {
    case LinkType::kEthernet: {
      auto eth = ParseEthernet(packet.data);
      if (!eth)
        return result;
      result.ethernet = *eth;
      if (eth->ether_type != ethertype::kIPv4 && eth->ether_type != ethertype::kIPv6) {
        return result;
      }
      DissectFromIp(result, eth->payload);
      break;
    }
    case LinkType::kNull:
    case LinkType::kLoop: {
      auto link = ParseNullLoop(packet.data, packet.link_type);
      if (!link)
        return result;
      if (link->ether_type != ethertype::kIPv4 && link->ether_type != ethertype::kIPv6) {
        return result;
      }
      DissectFromIp(result, link->payload);
      break;
    }
    case LinkType::kLinuxSll:
    case LinkType::kLinuxSll2: {
      auto link = ParseLinuxSll(packet.data, packet.link_type);
      if (!link)
        return result;
      if (link->ether_type != ethertype::kIPv4 && link->ether_type != ethertype::kIPv6) {
        return result;
      }
      DissectFromIp(result, link->payload);
      break;
    }
    case LinkType::kRaw: {
      auto link = ParseRawIp(packet.data);
      if (!link)
        return result;
      DissectFromIp(result, link->payload);
      break;
    }
    case LinkType::kUnknown:
    default:
      // Unknown link type — do not pretend this is Ethernet.
      break;
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
