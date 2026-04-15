// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/dissector/ethernet.h>

#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <vector>

namespace wirepeek::dissector {
namespace {

// Helper: build a minimal valid Ethernet II frame.
// dst(6) + src(6) + type(2) + payload
std::vector<uint8_t> MakeEthernetFrame(uint16_t ether_type,
                                       const std::vector<uint8_t>& payload = {0xDE, 0xAD}) {
  std::vector<uint8_t> frame;
  // Destination MAC: 00:11:22:33:44:55
  frame.insert(frame.end(), {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
  // Source MAC: 66:77:88:99:AA:BB
  frame.insert(frame.end(), {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB});
  // EtherType (big-endian)
  frame.push_back(static_cast<uint8_t>(ether_type >> 8));
  frame.push_back(static_cast<uint8_t>(ether_type & 0xFF));
  // Payload
  frame.insert(frame.end(), payload.begin(), payload.end());
  return frame;
}

TEST(EthernetTest, ParseValidIPv4Frame) {
  auto frame = MakeEthernetFrame(ethertype::kIPv4);
  auto result = ParseEthernet(frame);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->ether_type, ethertype::kIPv4);
  EXPECT_FALSE(result->vlan_id.has_value());
  EXPECT_EQ(result->payload.size(), 2u);
  EXPECT_EQ(result->payload[0], 0xDE);
  EXPECT_EQ(result->payload[1], 0xAD);

  // Check MACs.
  MacAddress expected_dst = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  MacAddress expected_src = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
  EXPECT_EQ(result->dst_mac, expected_dst);
  EXPECT_EQ(result->src_mac, expected_src);
}

TEST(EthernetTest, ParseIPv6Frame) {
  auto frame = MakeEthernetFrame(ethertype::kIPv6);
  auto result = ParseEthernet(frame);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->ether_type, ethertype::kIPv6);
}

TEST(EthernetTest, ParseVlanTaggedFrame) {
  // Build: dst(6) + src(6) + 0x8100(2) + TCI(2) + real_type(2) + payload
  std::vector<uint8_t> frame;
  frame.insert(frame.end(), {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});  // dst
  frame.insert(frame.end(), {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB});  // src
  frame.insert(frame.end(), {0x81, 0x00});                          // VLAN TPID
  frame.insert(frame.end(), {0x00, 0x64});                          // TCI: VLAN ID = 100
  frame.insert(frame.end(), {0x08, 0x00});                          // Real type: IPv4
  frame.insert(frame.end(), {0xCA, 0xFE});                          // payload

  auto result = ParseEthernet(frame);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->ether_type, ethertype::kIPv4);
  ASSERT_TRUE(result->vlan_id.has_value());
  EXPECT_EQ(*result->vlan_id, 100);
  EXPECT_EQ(result->payload.size(), 2u);
  EXPECT_EQ(result->payload[0], 0xCA);
}

TEST(EthernetTest, TruncatedFrame) {
  // Only 10 bytes — less than the minimum 14-byte Ethernet header.
  std::vector<uint8_t> frame(10, 0x00);
  auto result = ParseEthernet(frame);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), DissectError::kTruncated);
}

TEST(EthernetTest, TruncatedVlanFrame) {
  // 14 bytes with VLAN TPID but no room for TCI + real EtherType.
  std::vector<uint8_t> frame;
  frame.insert(frame.end(), {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});  // dst
  frame.insert(frame.end(), {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB});  // src
  frame.insert(frame.end(), {0x81, 0x00});                          // VLAN TPID
  // Missing TCI + real EtherType.

  auto result = ParseEthernet(frame);
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), DissectError::kTruncated);
}

TEST(EthernetTest, EmptyPayload) {
  auto frame = MakeEthernetFrame(ethertype::kIPv4, {});
  auto result = ParseEthernet(frame);

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->payload.empty());
}

TEST(EthernetTest, FormatMacAddress) {
  MacAddress mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
  EXPECT_EQ(FormatMac(mac), "aa:bb:cc:dd:ee:ff");
}

}  // namespace
}  // namespace wirepeek::dissector
