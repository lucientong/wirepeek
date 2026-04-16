// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/websocket.h>

#include <cstdint>
#include <gtest/gtest.h>
#include <vector>

namespace wirepeek::protocol {
namespace {

TEST(WebSocketTest, DetectUpgrade) {
  wirepeek::HttpRequest req;
  req.method = "GET";
  req.url = "/ws";
  req.headers = {
      {"Upgrade", "websocket"},
      {"Connection", "Upgrade"},
      {"Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="},
  };
  EXPECT_TRUE(IsWebSocketUpgrade(req));
}

TEST(WebSocketTest, NotUpgradeWithoutHeaders) {
  wirepeek::HttpRequest req;
  req.method = "GET";
  req.url = "/api";
  EXPECT_FALSE(IsWebSocketUpgrade(req));
}

TEST(WebSocketTest, NotUpgradeMissingConnection) {
  wirepeek::HttpRequest req;
  req.headers = {{"Upgrade", "websocket"}};
  EXPECT_FALSE(IsWebSocketUpgrade(req));
}

TEST(WebSocketTest, CaseInsensitive) {
  wirepeek::HttpRequest req;
  req.headers = {
      {"upgrade", "WebSocket"},
      {"connection", "upgrade"},
  };
  EXPECT_TRUE(IsWebSocketUpgrade(req));
}

TEST(WebSocketTest, ParseTextFrame) {
  // FIN=1, opcode=1 (text), mask=0, len=5
  std::vector<uint8_t> frame = {0x81, 0x05, 'h', 'e', 'l', 'l', 'o'};
  auto result = ParseWsFrame(frame);

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->fin);
  EXPECT_EQ(result->opcode, 1);  // text
  EXPECT_FALSE(result->masked);
  EXPECT_EQ(result->payload_len, 5u);
}

TEST(WebSocketTest, ParseMaskedFrame) {
  // FIN=1, opcode=2 (binary), mask=1, len=3
  std::vector<uint8_t> frame = {0x82, 0x83, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03};
  auto result = ParseWsFrame(frame);

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->masked);
  EXPECT_EQ(result->opcode, 2);
  EXPECT_EQ(result->payload_len, 3u);
}

TEST(WebSocketTest, ParseExtendedLength16) {
  // FIN=1, opcode=2, mask=0, len=126 (extended 16-bit), actual length=256
  std::vector<uint8_t> frame = {0x82, 126, 0x01, 0x00};
  auto result = ParseWsFrame(frame);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->payload_len, 256u);
}

TEST(WebSocketTest, ParsePingFrame) {
  std::vector<uint8_t> frame = {0x89, 0x00};  // FIN=1, opcode=9 (ping), len=0
  auto result = ParseWsFrame(frame);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->opcode, 9);
  EXPECT_TRUE(result->fin);
  EXPECT_EQ(result->payload_len, 0u);
}

TEST(WebSocketTest, TruncatedFrame) {
  std::vector<uint8_t> frame = {0x81};  // Only 1 byte.
  EXPECT_FALSE(ParseWsFrame(frame).has_value());
}

}  // namespace
}  // namespace wirepeek::protocol
