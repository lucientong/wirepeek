// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/http2.h>

#include <gtest/gtest.h>

TEST(Http2ParserTest, ReadsFrameAndPlainHpackHeaders) {
  std::vector<wirepeek::Http2StreamEvent> events;
  wirepeek::protocol::Http2Parser parser(
      [&](const wirepeek::Http2StreamEvent& event) { events.push_back(event); });

  const std::string preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
  std::vector<uint8_t> bytes(preface.begin(), preface.end());
  const std::vector<uint8_t> block = {0x82, 0x04, 0x06, '/', 'u', 's', 'e', 'r', 's'};
  bytes.insert(bytes.end(), {0x00, 0x00, static_cast<uint8_t>(block.size()), 0x01, 0x04, 0x00, 0x00,
                             0x00, 0x01});
  bytes.insert(bytes.end(), block.begin(), block.end());

  parser.Feed(bytes, wirepeek::StreamDirection::kClientToServer, {});
  ASSERT_EQ(events.size(), 1);
  EXPECT_EQ(events[0].stream_id, 1);
  EXPECT_EQ(events[0].frame_type, 1);
  EXPECT_EQ(events[0].method, "GET");
  EXPECT_EQ(events[0].path, "/users");
}
