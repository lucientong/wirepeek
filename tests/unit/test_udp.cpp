// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/dissector/udp.h>

#include <cstdint>
#include <gtest/gtest.h>
#include <vector>

namespace wirepeek::dissector {
namespace {

// Build a minimal valid UDP header (8 bytes) + payload.
std::vector<uint8_t> MakeUdpDatagram(uint16_t src_port, uint16_t dst_port,
                                     const std::vector<uint8_t>& payload = {0xAB, 0xCD}) {
  uint16_t length = 8 + static_cast<uint16_t>(payload.size());
  std::vector<uint8_t> dgram = {
      static_cast<uint8_t>(src_port >> 8),
      static_cast<uint8_t>(src_port & 0xFF),
      static_cast<uint8_t>(dst_port >> 8),
      static_cast<uint8_t>(dst_port & 0xFF),
      static_cast<uint8_t>(length >> 8),
      static_cast<uint8_t>(length & 0xFF),
      0x00,
      0x00,  // Checksum (not validated)
  };
  dgram.insert(dgram.end(), payload.begin(), payload.end());
  return dgram;
}

TEST(UdpTest, ParseValidDatagram) {
  auto dgram = MakeUdpDatagram(12345, 53);
  auto result = ParseUdp(dgram);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->src_port, 12345);
  EXPECT_EQ(result->dst_port, 53);
  EXPECT_EQ(result->length, 10);  // 8 header + 2 payload
  EXPECT_EQ(result->payload.size(), 2u);
  EXPECT_EQ(result->payload[0], 0xAB);
  EXPECT_EQ(result->payload[1], 0xCD);
}

TEST(UdpTest, EmptyPayload) {
  auto dgram = MakeUdpDatagram(1000, 2000, {});
  auto result = ParseUdp(dgram);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->length, 8);
  EXPECT_TRUE(result->payload.empty());
}

TEST(UdpTest, TruncatedHeader) {
  std::vector<uint8_t> dgram(4, 0x00);  // Less than 8 bytes.
  auto result = ParseUdp(dgram);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), DissectError::kTruncated);
}

TEST(UdpTest, LargePayload) {
  std::vector<uint8_t> payload(500, 0xFF);
  auto dgram = MakeUdpDatagram(8080, 9090, payload);
  auto result = ParseUdp(dgram);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->payload.size(), 500u);
}

}  // namespace
}  // namespace wirepeek::dissector
