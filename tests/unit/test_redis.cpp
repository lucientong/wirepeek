// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/redis.h>

#include <gtest/gtest.h>

TEST(RedisParserTest, ParsesIncrementalRequestResponse) {
  std::vector<wirepeek::RedisTransaction> transactions;
  wirepeek::protocol::RedisParser parser(
      [&](const wirepeek::RedisTransaction& transaction) {
        transactions.push_back(transaction);
      });
  const auto start = wirepeek::Timestamp(std::chrono::microseconds(100));
  const auto end = wirepeek::Timestamp(std::chrono::microseconds(350));
  const std::string request = "*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
  const std::string response = "$5\r\nvalue\r\n";
  parser.Feed(std::span<const uint8_t>(
                  reinterpret_cast<const uint8_t*>(request.data()), 7),
              wirepeek::StreamDirection::kClientToServer, start);
  parser.Feed(std::span<const uint8_t>(
                  reinterpret_cast<const uint8_t*>(request.data() + 7), request.size() - 7),
              wirepeek::StreamDirection::kClientToServer, start);
  parser.Feed(std::span<const uint8_t>(
                  reinterpret_cast<const uint8_t*>(response.data()), response.size()),
              wirepeek::StreamDirection::kServerToClient, end);

  ASSERT_EQ(transactions.size(), 1);
  EXPECT_EQ(transactions[0].command, "GET");
  EXPECT_EQ(transactions[0].args_summary, "key");
  EXPECT_EQ(transactions[0].response_summary, "value");
  EXPECT_EQ(transactions[0].latency.count(), 250);
  EXPECT_TRUE(transactions[0].complete);
}

TEST(RedisParserTest, MarksErrorResponse) {
  std::vector<wirepeek::RedisTransaction> transactions;
  wirepeek::protocol::RedisParser parser(
      [&](const wirepeek::RedisTransaction& transaction) {
        transactions.push_back(transaction);
      });
  const std::string request = "*1\r\n$4\r\nPING\r\n";
  const std::string response = "-ERR nope\r\n";
  parser.Feed(std::span<const uint8_t>(
                  reinterpret_cast<const uint8_t*>(request.data()), request.size()),
              wirepeek::StreamDirection::kClientToServer, {});
  parser.Feed(std::span<const uint8_t>(
                  reinterpret_cast<const uint8_t*>(response.data()), response.size()),
              wirepeek::StreamDirection::kServerToClient, {});
  ASSERT_EQ(transactions.size(), 1);
  EXPECT_TRUE(transactions[0].error);
}
