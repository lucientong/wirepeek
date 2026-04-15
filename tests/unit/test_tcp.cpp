// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/dissector/tcp.h>

#include <cstdint>
#include <gtest/gtest.h>
#include <vector>

namespace wirepeek::dissector {
namespace {

// Build a minimal valid TCP header (20 bytes, no options).
std::vector<uint8_t> MakeTcpHeader(uint16_t src_port, uint16_t dst_port, uint8_t flags,
                                   const std::vector<uint8_t>& payload = {}) {
  std::vector<uint8_t> seg = {
      static_cast<uint8_t>(src_port >> 8),
      static_cast<uint8_t>(src_port & 0xFF),  // Src port
      static_cast<uint8_t>(dst_port >> 8),
      static_cast<uint8_t>(dst_port & 0xFF),  // Dst port
      0x00,
      0x00,
      0x00,
      0x01,  // Seq = 1
      0x00,
      0x00,
      0x00,
      0x00,   // Ack = 0
      0x50,   // Data offset = 5 (20 bytes), Reserved = 0
      flags,  // Flags
      0xFF,
      0xFF,  // Window size = 65535
      0x00,
      0x00,  // Checksum (not validated)
      0x00,
      0x00,  // Urgent pointer
  };
  seg.insert(seg.end(), payload.begin(), payload.end());
  return seg;
}

// Build a TCP header with options (data offset > 5).
std::vector<uint8_t> MakeTcpHeaderWithOptions(uint16_t src_port, uint16_t dst_port, uint8_t flags) {
  // Header with MSS option: data offset = 6 (24 bytes).
  std::vector<uint8_t> seg = {
      static_cast<uint8_t>(src_port >> 8),
      static_cast<uint8_t>(src_port & 0xFF),
      static_cast<uint8_t>(dst_port >> 8),
      static_cast<uint8_t>(dst_port & 0xFF),
      0x00,
      0x00,
      0x00,
      0x01,  // Seq
      0x00,
      0x00,
      0x00,
      0x00,  // Ack
      0x60,  // Data offset = 6 (24 bytes)
      flags,
      0xFF,
      0xFF,  // Window
      0x00,
      0x00,  // Checksum
      0x00,
      0x00,  // Urgent pointer
      // MSS option: Kind=2, Length=4, Value=1460
      0x02,
      0x04,
      0x05,
      0xB4,
  };
  return seg;
}

TEST(TcpTest, ParseSynPacket) {
  auto seg = MakeTcpHeader(12345, 80, tcp_flags::kSYN);
  auto result = ParseTcp(seg);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->src_port, 12345);
  EXPECT_EQ(result->dst_port, 80);
  EXPECT_EQ(result->seq_num, 1u);
  EXPECT_EQ(result->ack_num, 0u);
  EXPECT_EQ(result->flags, tcp_flags::kSYN);
  EXPECT_EQ(result->header_length, 20);
  EXPECT_EQ(result->window_size, 65535);
  EXPECT_TRUE(result->payload.empty());
}

TEST(TcpTest, ParseSynAckPacket) {
  auto seg = MakeTcpHeader(80, 12345, tcp_flags::kSYN | tcp_flags::kACK);
  auto result = ParseTcp(seg);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->flags, tcp_flags::kSYN | tcp_flags::kACK);
}

TEST(TcpTest, ParseDataPacket) {
  std::vector<uint8_t> payload = {0x48, 0x54, 0x54, 0x50};  // "HTTP"
  auto seg = MakeTcpHeader(80, 12345, tcp_flags::kACK | tcp_flags::kPSH, payload);
  auto result = ParseTcp(seg);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->payload.size(), 4u);
  EXPECT_EQ(result->payload[0], 0x48);  // 'H'
}

TEST(TcpTest, ParseWithOptions) {
  auto seg = MakeTcpHeaderWithOptions(443, 54321, tcp_flags::kSYN);
  auto result = ParseTcp(seg);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->header_length, 24);
  EXPECT_EQ(result->data_offset, 6);
  EXPECT_TRUE(result->payload.empty());
}

TEST(TcpTest, TruncatedHeader) {
  std::vector<uint8_t> seg(10, 0x00);  // Less than 20 bytes.
  auto result = ParseTcp(seg);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), DissectError::kTruncated);
}

TEST(TcpTest, InvalidDataOffset) {
  // Data offset = 1 (4 bytes) — less than minimum 5 (20 bytes).
  std::vector<uint8_t> seg(20, 0x00);
  seg[12] = 0x10;  // data_offset = 1
  auto result = ParseTcp(seg);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), DissectError::kInvalidHeader);
}

TEST(TcpTest, FormatFlags) {
  EXPECT_EQ(FormatTcpFlags(tcp_flags::kSYN), "[SYN]");
  EXPECT_EQ(FormatTcpFlags(tcp_flags::kSYN | tcp_flags::kACK), "[SYN, ACK]");
  EXPECT_EQ(FormatTcpFlags(tcp_flags::kFIN | tcp_flags::kACK), "[ACK, FIN]");
  EXPECT_EQ(FormatTcpFlags(0), "[]");
}

TEST(TcpTest, FormatFlagsAllIndividual) {
  EXPECT_EQ(FormatTcpFlags(tcp_flags::kFIN), "[FIN]");
  EXPECT_EQ(FormatTcpFlags(tcp_flags::kACK), "[ACK]");
  EXPECT_EQ(FormatTcpFlags(tcp_flags::kRST), "[RST]");
  EXPECT_EQ(FormatTcpFlags(tcp_flags::kPSH), "[PSH]");
  EXPECT_EQ(FormatTcpFlags(tcp_flags::kURG), "[URG]");
  EXPECT_EQ(FormatTcpFlags(tcp_flags::kECE), "[ECE]");
  EXPECT_EQ(FormatTcpFlags(tcp_flags::kCWR), "[CWR]");
}

TEST(TcpTest, FormatFlagsAllCombined) {
  uint8_t all = tcp_flags::kFIN | tcp_flags::kSYN | tcp_flags::kRST | tcp_flags::kPSH |
                tcp_flags::kACK | tcp_flags::kURG | tcp_flags::kECE | tcp_flags::kCWR;
  auto result = FormatTcpFlags(all);
  EXPECT_NE(result.find("SYN"), std::string::npos);
  EXPECT_NE(result.find("ACK"), std::string::npos);
  EXPECT_NE(result.find("FIN"), std::string::npos);
  EXPECT_NE(result.find("RST"), std::string::npos);
  EXPECT_NE(result.find("PSH"), std::string::npos);
  EXPECT_NE(result.find("URG"), std::string::npos);
  EXPECT_NE(result.find("ECE"), std::string::npos);
  EXPECT_NE(result.find("CWR"), std::string::npos);
}

}  // namespace
}  // namespace wirepeek::dissector
