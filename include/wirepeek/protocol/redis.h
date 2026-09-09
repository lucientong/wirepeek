// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <wirepeek/request.h>
#include <wirepeek/stream.h>

#include <array>
#include <deque>
#include <functional>
#include <span>
#include <string>
#include <vector>

namespace wirepeek::protocol {

class RedisParser {
 public:
  using TransactionCallback = std::function<void(const RedisTransaction&)>;

  explicit RedisParser(TransactionCallback callback) : callback_(std::move(callback)) {}
  void Feed(std::span<const uint8_t> data, StreamDirection direction, Timestamp timestamp);
  void OnClose();

 private:
  struct Value {
    std::string text;
    std::vector<Value> items;
    bool error = false;
  };
  struct Pending {
    std::string command;
    std::string args;
    Timestamp timestamp;
  };

  static bool ParseValue(std::string_view input, size_t& consumed, Value& value, int depth = 0);
  static std::string Summarize(const Value& value);
  void ParseDirection(size_t index, Timestamp timestamp);

  TransactionCallback callback_;
  std::array<std::string, 2> buffers_;
  std::deque<Pending> pending_;
};

}  // namespace wirepeek::protocol
