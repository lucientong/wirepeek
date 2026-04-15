// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/packet.h>

#include <cstdint>
#include <gtest/gtest.h>
#include <vector>

namespace wirepeek {
namespace {

TEST(OwnedPacketTest, CopiesDataFromView) {
  std::vector<uint8_t> raw = {0x01, 0x02, 0x03, 0x04, 0x05};
  auto now =
      std::chrono::time_point_cast<std::chrono::microseconds>(std::chrono::system_clock::now());

  PacketView view{
      .data = raw,
      .timestamp = now,
      .capture_length = 5,
      .original_length = 100,
  };

  OwnedPacket owned(view);

  // Data should be a copy, not a reference.
  ASSERT_EQ(owned.data.size(), 5u);
  EXPECT_EQ(owned.data[0], 0x01);
  EXPECT_EQ(owned.data[4], 0x05);
  EXPECT_EQ(owned.timestamp, now);
  EXPECT_EQ(owned.original_length, 100u);

  // Verify it's a real copy — modifying original shouldn't affect owned.
  raw[0] = 0xFF;
  EXPECT_EQ(owned.data[0], 0x01);
}

TEST(OwnedPacketTest, ViewReturnsValidPacketView) {
  std::vector<uint8_t> raw = {0xAA, 0xBB, 0xCC};
  auto now =
      std::chrono::time_point_cast<std::chrono::microseconds>(std::chrono::system_clock::now());

  PacketView original{
      .data = raw,
      .timestamp = now,
      .capture_length = 3,
      .original_length = 50,
  };

  OwnedPacket owned(original);
  PacketView back = owned.View();

  EXPECT_EQ(back.data.size(), 3u);
  EXPECT_EQ(back.data[0], 0xAA);
  EXPECT_EQ(back.data[2], 0xCC);
  EXPECT_EQ(back.timestamp, now);
  EXPECT_EQ(back.capture_length, 3u);
  EXPECT_EQ(back.original_length, 50u);

  // The view should reference the owned data, not the original.
  EXPECT_EQ(back.data.data(), owned.data.data());
}

TEST(OwnedPacketTest, EmptyPacket) {
  std::vector<uint8_t> empty;
  PacketView view{.data = empty, .capture_length = 0, .original_length = 0};

  OwnedPacket owned(view);
  EXPECT_TRUE(owned.data.empty());
  EXPECT_EQ(owned.original_length, 0u);

  PacketView back = owned.View();
  EXPECT_TRUE(back.data.empty());
}

}  // namespace
}  // namespace wirepeek
