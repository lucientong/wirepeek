// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/redis.h>

#include <charconv>

namespace wirepeek::protocol {
namespace {

bool ParseNumber(std::string_view value, int64_t& result) {
  const auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), result);
  return ec == std::errc{} && ptr == value.data() + value.size();
}

}  // namespace

bool RedisParser::ParseValue(std::string_view input, size_t& consumed, Value& value, int depth) {
  consumed = 0;
  if (input.empty() || depth > 32)
    return false;
  const auto crlf = input.find("\r\n", 1);
  if (crlf == std::string_view::npos)
    return false;
  const char type = input[0];
  const auto line = input.substr(1, crlf - 1);
  const size_t header_size = crlf + 2;

  if (type == '+' || type == '-' || type == ':') {
    value.text = std::string(line);
    value.error = type == '-';
    consumed = header_size;
    return true;
  }

  int64_t length = 0;
  if ((type != '$' && type != '*') || !ParseNumber(line, length) || length < -1)
    return false;
  if (length == -1) {
    value.text = "(nil)";
    consumed = header_size;
    return true;
  }

  if (type == '$') {
    const size_t size = static_cast<size_t>(length);
    if (input.size() < header_size + size + 2 || input.substr(header_size + size, 2) != "\r\n")
      return false;
    value.text = std::string(input.substr(header_size, size));
    consumed = header_size + size + 2;
    return true;
  }

  size_t offset = header_size;
  value.items.reserve(static_cast<size_t>(length));
  for (int64_t i = 0; i < length; ++i) {
    Value item;
    size_t item_size = 0;
    if (!ParseValue(input.substr(offset), item_size, item, depth + 1))
      return false;
    offset += item_size;
    value.items.push_back(std::move(item));
  }
  consumed = offset;
  return true;
}

std::string RedisParser::Summarize(const Value& value) {
  if (value.items.empty())
    return value.text.size() > 128 ? value.text.substr(0, 125) + "..." : value.text;
  std::string result;
  for (const auto& item : value.items) {
    if (!result.empty())
      result.push_back(' ');
    result += Summarize(item);
    if (result.size() > 128) {
      result.resize(125);
      result += "...";
      break;
    }
  }
  return result;
}

void RedisParser::Feed(std::span<const uint8_t> data, StreamDirection direction,
                       Timestamp timestamp) {
  const size_t index = direction == StreamDirection::kClientToServer ? 0 : 1;
  auto& buffer = buffers_[index];
  if (buffer.size() + data.size() > 16 * 1024 * 1024) {
    buffer.clear();
    return;
  }
  buffer.append(reinterpret_cast<const char*>(data.data()), data.size());
  ParseDirection(index, timestamp);
}

void RedisParser::ParseDirection(size_t index, Timestamp timestamp) {
  auto& buffer = buffers_[index];
  while (!buffer.empty()) {
    Value value;
    size_t consumed = 0;
    if (!ParseValue(buffer, consumed, value))
      return;
    buffer.erase(0, consumed);

    if (index == 0) {
      Pending pending;
      pending.timestamp = timestamp;
      if (!value.items.empty()) {
        pending.command = Summarize(value.items.front());
        for (size_t i = 1; i < value.items.size(); ++i) {
          if (!pending.args.empty())
            pending.args.push_back(' ');
          pending.args += Summarize(value.items[i]);
        }
      } else {
        pending.command = Summarize(value);
      }
      pending_.push_back(std::move(pending));
      continue;
    }

    if (pending_.empty())
      continue;
    auto pending = std::move(pending_.front());
    pending_.pop_front();
    RedisTransaction transaction{
        .command = std::move(pending.command),
        .args_summary = std::move(pending.args),
        .response_summary = Summarize(value),
        .latency =
            std::chrono::duration_cast<std::chrono::microseconds>(timestamp - pending.timestamp),
        .timestamp = pending.timestamp,
        .error = value.error,
        .complete = true,
    };
    if (callback_)
      callback_(transaction);
  }
}

void RedisParser::OnClose() {
  while (!pending_.empty()) {
    auto pending = std::move(pending_.front());
    pending_.pop_front();
    if (callback_)
      callback_(RedisTransaction{.command = std::move(pending.command),
                                 .args_summary = std::move(pending.args),
                                 .timestamp = pending.timestamp});
  }
}

}  // namespace wirepeek::protocol
