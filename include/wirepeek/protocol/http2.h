// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <wirepeek/request.h>
#include <wirepeek/stream.h>

#include <array>
#include <functional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace wirepeek::protocol {

class Http2Parser {
 public:
  using EventCallback = std::function<void(const Http2StreamEvent&)>;

  explicit Http2Parser(EventCallback callback) : callback_(std::move(callback)) {}
  void Feed(std::span<const uint8_t> data, StreamDirection direction, Timestamp timestamp);

 private:
  struct StreamHeaders {
    std::string method;
    std::string path;
    uint16_t status = 0;
    bool grpc = false;
    std::optional<int> grpc_status;
  };

  void ParseFrames(size_t index, Timestamp timestamp);
  void DecodeHeaders(uint32_t stream_id, std::span<const uint8_t> block);

  EventCallback callback_;
  std::array<std::vector<uint8_t>, 2> buffers_;
  std::unordered_map<uint32_t, StreamHeaders> streams_;
  bool preface_consumed_ = false;
};

}  // namespace wirepeek::protocol
