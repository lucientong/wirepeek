// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/dissector/dissect.h>

#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace wirepeek::dissector {
namespace {

// Helper: build a complete raw Ethernet + IPv4 + TCP packet.
std::vector<uint8_t> MakeFullTcpPacket(uint16_t src_port, uint16_t dst_port, uint8_t tcp_flags,
                                       const std::vector<uint8_t>& tcp_payload = {}) {
  // TCP header (20 bytes)
  std::vector<uint8_t> tcp = {
      static_cast<uint8_t>(src_port >> 8),
      static_cast<uint8_t>(src_port & 0xFF),
      static_cast<uint8_t>(dst_port >> 8),
      static_cast<uint8_t>(dst_port & 0xFF),
      0x00,
      0x00,
      0x00,
      0x01,  // Seq = 1
      0x00,
      0x00,
      0x00,
      0x00,  // Ack = 0
      0x50,
      tcp_flags,  // Data offset = 5, flags
      0xFF,
      0xFF,  // Window
      0x00,
      0x00,  // Checksum
      0x00,
      0x00,  // Urgent pointer
  };
  tcp.insert(tcp.end(), tcp_payload.begin(), tcp_payload.end());

  // IPv4 header (20 bytes)
  uint16_t ip_total = 20 + static_cast<uint16_t>(tcp.size());
  std::vector<uint8_t> ip = {
      0x45,
      0x00,
      static_cast<uint8_t>(ip_total >> 8),
      static_cast<uint8_t>(ip_total & 0xFF),
      0x00,
      0x00,
      0x40,
      0x00,
      0x40,
      0x06,  // TTL=64, protocol=TCP
      0x00,
      0x00,  // Checksum
      0xC0,
      0xA8,
      0x01,
      0x0A,  // Src: 192.168.1.10
      0x0A,
      0x00,
      0x00,
      0x01,  // Dst: 10.0.0.1
  };
  ip.insert(ip.end(), tcp.begin(), tcp.end());

  // Ethernet header (14 bytes)
  std::vector<uint8_t> pkt = {
      0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // Dst MAC
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66,  // Src MAC
      0x08, 0x00,                          // EtherType: IPv4
  };
  pkt.insert(pkt.end(), ip.begin(), ip.end());
  return pkt;
}

// Helper: build a complete raw Ethernet + IPv4 + UDP packet.
std::vector<uint8_t> MakeFullUdpPacket(uint16_t src_port, uint16_t dst_port,
                                       const std::vector<uint8_t>& udp_payload = {}) {
  uint16_t udp_len = 8 + static_cast<uint16_t>(udp_payload.size());
  std::vector<uint8_t> udp = {
      static_cast<uint8_t>(src_port >> 8),
      static_cast<uint8_t>(src_port & 0xFF),
      static_cast<uint8_t>(dst_port >> 8),
      static_cast<uint8_t>(dst_port & 0xFF),
      static_cast<uint8_t>(udp_len >> 8),
      static_cast<uint8_t>(udp_len & 0xFF),
      0x00,
      0x00,  // Checksum
  };
  udp.insert(udp.end(), udp_payload.begin(), udp_payload.end());

  uint16_t ip_total = 20 + static_cast<uint16_t>(udp.size());
  std::vector<uint8_t> ip = {
      0x45,
      0x00,
      static_cast<uint8_t>(ip_total >> 8),
      static_cast<uint8_t>(ip_total & 0xFF),
      0x00,
      0x00,
      0x40,
      0x00,
      0x40,
      0x11,  // TTL=64, protocol=UDP
      0x00,
      0x00,
      0xC0,
      0xA8,
      0x01,
      0x0A,  // Src: 192.168.1.10
      0x0A,
      0x00,
      0x00,
      0x01,  // Dst: 10.0.0.1
  };
  ip.insert(ip.end(), udp.begin(), udp.end());

  std::vector<uint8_t> pkt = {
      0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00,
  };
  pkt.insert(pkt.end(), ip.begin(), ip.end());
  return pkt;
}

// ── Dissect() pipeline tests ──────────────────────────────────────────────────

TEST(DissectTest, FullTcpPacket) {
  auto raw = MakeFullTcpPacket(12345, 80, tcp_flags::kSYN);
  PacketView view{.data = raw, .capture_length = static_cast<uint32_t>(raw.size())};

  auto result = Dissect(view);
  ASSERT_TRUE(result.ethernet.has_value());
  ASSERT_TRUE(result.ip.has_value());
  ASSERT_TRUE(result.tcp.has_value());
  EXPECT_FALSE(result.udp.has_value());

  EXPECT_EQ(result.ethernet->ether_type, ethertype::kIPv4);
  EXPECT_EQ(result.ip->version, 4);
  EXPECT_EQ(result.ip->protocol, ip_protocol::kTCP);
  EXPECT_EQ(result.tcp->src_port, 12345);
  EXPECT_EQ(result.tcp->dst_port, 80);
  EXPECT_EQ(result.tcp->flags, tcp_flags::kSYN);
}

TEST(DissectTest, FullUdpPacket) {
  auto raw = MakeFullUdpPacket(5353, 53, {0x01, 0x02});
  PacketView view{.data = raw, .capture_length = static_cast<uint32_t>(raw.size())};

  auto result = Dissect(view);
  ASSERT_TRUE(result.ethernet.has_value());
  ASSERT_TRUE(result.ip.has_value());
  EXPECT_FALSE(result.tcp.has_value());
  ASSERT_TRUE(result.udp.has_value());

  EXPECT_EQ(result.udp->src_port, 5353);
  EXPECT_EQ(result.udp->dst_port, 53);
  EXPECT_EQ(result.udp->payload.size(), 2u);
}

TEST(DissectTest, ArpPacket) {
  // Ethernet frame with ARP EtherType (0x0806).
  std::vector<uint8_t> pkt = {
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Dst: broadcast
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66,  // Src
      0x08, 0x06,                          // EtherType: ARP
      0x00, 0x01,                          // ARP payload (dummy)
  };
  PacketView view{.data = pkt, .capture_length = static_cast<uint32_t>(pkt.size())};

  auto result = Dissect(view);
  ASSERT_TRUE(result.ethernet.has_value());
  EXPECT_EQ(result.ethernet->ether_type, ethertype::kARP);
  EXPECT_FALSE(result.ip.has_value());
  EXPECT_FALSE(result.tcp.has_value());
  EXPECT_FALSE(result.udp.has_value());
}

TEST(DissectTest, TruncatedIpPayload) {
  // Ethernet header says IPv4, but IP payload is only 5 bytes (< 20 min).
  std::vector<uint8_t> pkt = {
      0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00,  // IPv4
      0x45, 0x00, 0x00, 0x14, 0x00,  // 5 bytes of truncated IP
  };
  PacketView view{.data = pkt, .capture_length = static_cast<uint32_t>(pkt.size())};

  auto result = Dissect(view);
  ASSERT_TRUE(result.ethernet.has_value());
  EXPECT_FALSE(result.ip.has_value());  // IP parse should fail
}

TEST(DissectTest, IpWithUnknownProtocol) {
  // IPv4 with protocol=99 (not TCP or UDP).
  std::vector<uint8_t> ip = {
      0x45, 0x00, 0x00, 0x16,                                                  // Total length = 22
      0x00, 0x00, 0x40, 0x00, 0x40, 0x63,                                      // Protocol = 99
      0x00, 0x00, 0xC0, 0xA8, 0x01, 0x01, 0x0A, 0x00, 0x00, 0x01, 0xDE, 0xAD,  // Payload
  };
  std::vector<uint8_t> pkt = {
      0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00,
  };
  pkt.insert(pkt.end(), ip.begin(), ip.end());
  PacketView view{.data = pkt, .capture_length = static_cast<uint32_t>(pkt.size())};

  auto result = Dissect(view);
  ASSERT_TRUE(result.ip.has_value());
  EXPECT_EQ(result.ip->protocol, 99);
  EXPECT_FALSE(result.tcp.has_value());
  EXPECT_FALSE(result.udp.has_value());
}

TEST(DissectTest, EmptyPacket) {
  std::vector<uint8_t> empty;
  PacketView view{.data = empty};

  auto result = Dissect(view);
  EXPECT_FALSE(result.ethernet.has_value());
  EXPECT_FALSE(result.ip.has_value());
}

// ── FormatSummary() tests ─────────────────────────────────────────────────────

TEST(FormatSummaryTest, TcpPacket) {
  auto raw = MakeFullTcpPacket(12345, 80, tcp_flags::kSYN);
  PacketView view{.data = raw, .capture_length = static_cast<uint32_t>(raw.size())};

  auto result = Dissect(view);
  auto summary = FormatSummary(result);

  EXPECT_NE(summary.find("192.168.1.10"), std::string::npos);
  EXPECT_NE(summary.find("10.0.0.1"), std::string::npos);
  EXPECT_NE(summary.find("12345"), std::string::npos);
  EXPECT_NE(summary.find("80"), std::string::npos);
  EXPECT_NE(summary.find("TCP"), std::string::npos);
  EXPECT_NE(summary.find("[SYN]"), std::string::npos);
}

TEST(FormatSummaryTest, UdpPacket) {
  auto raw = MakeFullUdpPacket(5353, 53, {0x01});
  PacketView view{.data = raw, .capture_length = static_cast<uint32_t>(raw.size())};

  auto result = Dissect(view);
  auto summary = FormatSummary(result);

  EXPECT_NE(summary.find("UDP"), std::string::npos);
  EXPECT_NE(summary.find("5353"), std::string::npos);
  EXPECT_NE(summary.find("53"), std::string::npos);
  EXPECT_NE(summary.find("len=1"), std::string::npos);
}

TEST(FormatSummaryTest, EthernetOnlyArp) {
  std::vector<uint8_t> pkt = {
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x11, 0x22,
      0x33, 0x44, 0x55, 0x66, 0x08, 0x06, 0x00, 0x01,
  };
  PacketView view{.data = pkt, .capture_length = static_cast<uint32_t>(pkt.size())};

  auto result = Dissect(view);
  auto summary = FormatSummary(result);

  EXPECT_NE(summary.find("type=0x0806"), std::string::npos);
  EXPECT_NE(summary.find("11:22:33:44:55:66"), std::string::npos);
}

TEST(FormatSummaryTest, UnknownProtocol) {
  std::vector<uint8_t> ip = {
      0x45, 0x00, 0x00, 0x16, 0x00, 0x00, 0x40, 0x00, 0x40, 0x63, 0x00, 0x00,  // Protocol = 99
      0xC0, 0xA8, 0x01, 0x01, 0x0A, 0x00, 0x00, 0x01, 0xDE, 0xAD,
  };
  std::vector<uint8_t> pkt = {
      0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00,
  };
  pkt.insert(pkt.end(), ip.begin(), ip.end());
  PacketView view{.data = pkt, .capture_length = static_cast<uint32_t>(pkt.size())};

  auto result = Dissect(view);
  auto summary = FormatSummary(result);

  EXPECT_NE(summary.find("proto=99"), std::string::npos);
}

TEST(FormatSummaryTest, EmptyPacket) {
  DissectedPacket empty;
  EXPECT_EQ(FormatSummary(empty), "(unparsed)");
}

}  // namespace
}  // namespace wirepeek::dissector
