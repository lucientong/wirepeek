// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/http2.h>

#include <algorithm>
#include <charconv>
#include <cstring>
#include <string_view>

namespace wirepeek::protocol {
namespace {

constexpr std::string_view kPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

bool DecodeInteger(std::span<const uint8_t> input, uint8_t prefix_bits, size_t& offset,
                   uint32_t& value) {
  if (offset >= input.size())
    return false;
  const uint8_t mask = static_cast<uint8_t>((1U << prefix_bits) - 1U);
  value = input[offset] & mask;
  ++offset;
  if (value < mask)
    return true;
  uint32_t shift = 0;
  while (offset < input.size() && shift <= 28) {
    const uint8_t byte = input[offset++];
    value += static_cast<uint32_t>(byte & 0x7f) << shift;
    if ((byte & 0x80) == 0)
      return true;
    shift += 7;
  }
  return false;
}

bool DecodeString(std::span<const uint8_t> input, size_t& offset, std::string& value) {
  if (offset >= input.size() || (input[offset] & 0x80) != 0)
    return false;  // Huffman intentionally unsupported in the practical subset.
  uint32_t size = 0;
  if (!DecodeInteger(input, 7, offset, size) || size > input.size() - offset)
    return false;
  value.assign(reinterpret_cast<const char*>(input.data() + offset), size);
  offset += size;
  return true;
}

std::pair<std::string_view, std::string_view> StaticHeader(uint32_t index) {
  switch (index) {
    case 2:
      return {":method", "GET"};
    case 3:
      return {":method", "POST"};
    case 4:
      return {":path", "/"};
    case 5:
      return {":path", "/index.html"};
    case 8:
      return {":status", "200"};
    case 9:
      return {":status", "204"};
    case 10:
      return {":status", "206"};
    case 11:
      return {":status", "304"};
    case 12:
      return {":status", "400"};
    case 13:
      return {":status", "404"};
    case 14:
      return {":status", "500"};
    case 31:
      return {"content-type", ""};
    default:
      return {};
  }
}

}  // namespace

void Http2Parser::Feed(std::span<const uint8_t> data, StreamDirection direction,
                       Timestamp timestamp) {
  const size_t index = direction == StreamDirection::kClientToServer ? 0 : 1;
  auto& buffer = buffers_[index];
  if (buffer.size() + data.size() > 16 * 1024 * 1024) {
    buffer.clear();
    return;
  }
  buffer.insert(buffer.end(), data.begin(), data.end());

  if (index == 0 && !preface_consumed_) {
    const size_t compare = std::min(buffer.size(), kPreface.size());
    if (std::memcmp(buffer.data(), kPreface.data(), compare) != 0) {
      buffer.clear();
      return;
    }
    if (buffer.size() < kPreface.size())
      return;
    buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(kPreface.size()));
    preface_consumed_ = true;
  }
  ParseFrames(index, timestamp);
}

void Http2Parser::ParseFrames(size_t index, Timestamp timestamp) {
  auto& buffer = buffers_[index];
  while (buffer.size() >= 9) {
    const uint32_t length = (static_cast<uint32_t>(buffer[0]) << 16) |
                            (static_cast<uint32_t>(buffer[1]) << 8) | buffer[2];
    if (length > 16 * 1024 * 1024) {
      buffer.clear();
      return;
    }
    if (buffer.size() < 9 + length)
      return;
    const uint8_t type = buffer[3];
    const uint8_t flags = buffer[4];
    const uint32_t stream_id = ((static_cast<uint32_t>(buffer[5]) & 0x7f) << 24) |
                               (static_cast<uint32_t>(buffer[6]) << 16) |
                               (static_cast<uint32_t>(buffer[7]) << 8) | buffer[8];
    std::span<const uint8_t> payload(buffer.data() + 9, length);

    if (type == 1 && stream_id != 0) {
      size_t offset = 0;
      size_t payload_end = payload.size();
      if ((flags & 0x08) != 0 && !payload.empty()) {
        offset = 1;
        if (payload[0] > payload.size() - offset)
          offset = payload_end;
        else
          payload_end -= payload[0];
      }
      if ((flags & 0x20) != 0)
        offset = std::min(payload_end, offset + 5);
      if (offset <= payload_end)
        DecodeHeaders(stream_id, payload.subspan(offset, payload_end - offset));
    }

    const auto state = streams_.find(stream_id);
    Http2StreamEvent event{
        .stream_id = stream_id,
        .frame_type = type,
        .flags = flags,
        .payload_size = length,
        .timestamp = timestamp,
    };
    if (state != streams_.end()) {
      event.method = state->second.method;
      event.path = state->second.path;
      event.status = state->second.status;
      event.grpc = state->second.grpc;
      event.grpc_status = state->second.grpc_status;
    }
    if (callback_)
      callback_(event);
    buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(9 + length));
  }
}

void Http2Parser::DecodeHeaders(uint32_t stream_id, std::span<const uint8_t> block) {
  auto& state = streams_[stream_id];
  size_t offset = 0;
  while (offset < block.size()) {
    std::string name;
    std::string value;
    uint32_t index = 0;
    if ((block[offset] & 0x80) != 0) {
      if (!DecodeInteger(block, 7, offset, index))
        return;
      const auto header = StaticHeader(index);
      name = header.first;
      value = header.second;
    } else {
      const uint8_t prefix = (block[offset] & 0x40) != 0 ? 6 : 4;
      if (!DecodeInteger(block, prefix, offset, index))
        return;
      if (index == 0) {
        if (!DecodeString(block, offset, name))
          return;
      } else {
        name = StaticHeader(index).first;
      }
      if (name.empty() || !DecodeString(block, offset, value))
        return;
    }

    if (name == ":method")
      state.method = value;
    else if (name == ":path")
      state.path = value;
    else if (name == ":status") {
      unsigned parsed = 0;
      std::from_chars(value.data(), value.data() + value.size(), parsed);
      state.status = static_cast<uint16_t>(parsed);
    } else if (name == "content-type" && value.starts_with("application/grpc"))
      state.grpc = true;
    else if (name == "grpc-status") {
      int parsed = 0;
      std::from_chars(value.data(), value.data() + value.size(), parsed);
      state.grpc_status = parsed;
    }
  }
}

}  // namespace wirepeek::protocol
