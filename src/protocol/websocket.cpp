// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/websocket.h>

#include <algorithm>
#include <cctype>

namespace wirepeek::protocol {

bool IsWebSocketUpgrade(const HttpRequest& req) {
  bool has_upgrade = false;
  bool has_websocket = false;

  for (const auto& [name, value] : req.headers) {
    // Case-insensitive header name comparison.
    std::string lower_name = name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    if (lower_name == "upgrade") {
      std::string lower_value = value;
      std::transform(lower_value.begin(), lower_value.end(), lower_value.begin(),
                     [](unsigned char c) { return std::tolower(c); });
      if (lower_value == "websocket") {
        has_websocket = true;
      }
    }
    if (lower_name == "connection") {
      std::string lower_value = value;
      std::transform(lower_value.begin(), lower_value.end(), lower_value.begin(),
                     [](unsigned char c) { return std::tolower(c); });
      if (lower_value.find("upgrade") != std::string::npos) {
        has_upgrade = true;
      }
    }
  }

  return has_upgrade && has_websocket;
}

std::optional<WsFrameInfo> ParseWsFrame(std::span<const uint8_t> data) {
  if (data.size() < 2)
    return std::nullopt;

  WsFrameInfo info;
  info.fin = (data[0] & 0x80) != 0;
  info.opcode = data[0] & 0x0F;
  info.masked = (data[1] & 0x80) != 0;

  uint8_t len_byte = data[1] & 0x7F;

  if (len_byte <= 125) {
    info.payload_len = len_byte;
  } else if (len_byte == 126) {
    if (data.size() < 4)
      return std::nullopt;
    info.payload_len = (static_cast<size_t>(data[2]) << 8) | data[3];
  } else {
    // 127: 8-byte extended length.
    if (data.size() < 10)
      return std::nullopt;
    info.payload_len = 0;
    for (int i = 0; i < 8; ++i) {
      info.payload_len = (info.payload_len << 8) | data[2 + i];
    }
  }

  return info;
}

}  // namespace wirepeek::protocol
