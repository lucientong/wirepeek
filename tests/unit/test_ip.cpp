// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/dissector/ip.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

namespace wirepeek::dissector {
namespace {

// Build a minimal valid IPv4 header (20 bytes, no options).
std::vector<uint8_t> MakeIpv4Header(uint8_t protocol = ip_protocol::kTCP,
                                     const std::vector<uint8_t>& payload = {0x01, 0x02}) {
  uint16_t total_len = 20 + static_cast<uint16_t>(payload.size());
  std::vector<uint8_t> pkt = {
      0x45,                                                       // Version=4, IHL=5
      0x00,                                                       // DSCP/ECN
      static_cast<uint8_t>(total_len >> 8),                       // Total length (hi)
      static_cast<uint8_t>(total_len & 0xFF),                     // Total length (lo)
      0x00, 0x00,                                                 // Identification
      0x40, 0x00,                                                 // Flags=DF, Fragment offset=0
      0x40,                                                       // TTL=64
      protocol,                                                   // Protocol
      0x00, 0x00,                                                 // Checksum (not validated)
      0xC0, 0xA8, 0x01, 0x01,                                    // Src: 192.168.1.1
      0x0A, 0x00, 0x00, 0x01,                                    // Dst: 10.0.0.1
  };
  pkt.insert(pkt.end(), payload.begin(), payload.end());
  return pkt;
}

// Build a minimal valid IPv6 header (40 bytes).
std::vector<uint8_t> MakeIpv6Header(uint8_t next_header = ip_protocol::kTCP,
                                     const std::vector<uint8_t>& payload = {0x01, 0x02}) {
  uint16_t payload_len = static_cast<uint16_t>(payload.size());
  std::vector<uint8_t> pkt = {
      0x60, 0x00, 0x00, 0x00,                                    // Version=6, TC, Flow Label
      static_cast<uint8_t>(payload_len >> 8),                     // Payload length (hi)
      static_cast<uint8_t>(payload_len & 0xFF),                   // Payload length (lo)
      next_header,                                                // Next Header
      0x40,                                                       // Hop Limit=64
      // Src: ::1
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
      // Dst: ::2
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
  };
  pkt.insert(pkt.end(), payload.begin(), payload.end());
  return pkt;
}

TEST(IpTest, ParseValidIpv4) {
  auto pkt = MakeIpv4Header(ip_protocol::kTCP);
  auto result = ParseIp(pkt);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->version, 4);
  EXPECT_EQ(result->protocol, ip_protocol::kTCP);
  EXPECT_EQ(result->ttl, 64);
  EXPECT_EQ(result->header_length, 20);
  EXPECT_EQ(result->total_length, 22);  // 20 header + 2 payload
  EXPECT_EQ(result->payload.size(), 2u);

  // Check IP addresses.
  auto src = std::get<Ipv4Address>(result->src_ip);
  EXPECT_EQ(src, (Ipv4Address{192, 168, 1, 1}));
  auto dst = std::get<Ipv4Address>(result->dst_ip);
  EXPECT_EQ(dst, (Ipv4Address{10, 0, 0, 1}));
}

TEST(IpTest, ParseValidIpv6) {
  auto pkt = MakeIpv6Header(ip_protocol::kTCP);
  auto result = ParseIp(pkt);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->version, 6);
  EXPECT_EQ(result->protocol, ip_protocol::kTCP);
  EXPECT_EQ(result->ttl, 64);  // Hop limit
  EXPECT_EQ(result->header_length, 40);
  EXPECT_EQ(result->payload.size(), 2u);
}

TEST(IpTest, TruncatedIpv4) {
  // Only 10 bytes — less than minimum 20.
  std::vector<uint8_t> pkt(10, 0x45);
  pkt[0] = 0x45;  // Version=4, IHL=5
  auto result = ParseIp(pkt);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), DissectError::kTruncated);
}

TEST(IpTest, InvalidIHL) {
  // IHL=2 (minimum is 5) — invalid.
  std::vector<uint8_t> pkt(20, 0x00);
  pkt[0] = 0x42;  // Version=4, IHL=2
  auto result = ParseIp(pkt);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), DissectError::kInvalidHeader);
}

TEST(IpTest, UnsupportedVersion) {
  std::vector<uint8_t> pkt(20, 0x00);
  pkt[0] = 0x30;  // Version=3
  auto result = ParseIp(pkt);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), DissectError::kUnsupportedVersion);
}

TEST(IpTest, EmptyData) {
  std::span<const uint8_t> empty;
  auto result = ParseIp(empty);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), DissectError::kTruncated);
}

TEST(IpTest, FormatIpv4Address) {
  IpAddress addr = Ipv4Address{192, 168, 1, 100};
  EXPECT_EQ(FormatIp(addr), "192.168.1.100");
}

TEST(IpTest, FormatIpv6Address) {
  Ipv6Address v6 = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  IpAddress addr = v6;
  EXPECT_EQ(FormatIp(addr), "2001:0db8:0000:0000:0000:0000:0000:0001");
}

}  // namespace
}  // namespace wirepeek::dissector
