// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/detector.h>

#include <algorithm>
#include <cstring>
#include <string_view>

namespace wirepeek::protocol {

namespace {

bool StartsWith(std::span<const uint8_t> data, std::string_view prefix) {
  if (data.size() < prefix.size())
    return false;
  return std::memcmp(data.data(), prefix.data(), prefix.size()) == 0;
}

}  // namespace

AppProtocol DetectProtocol(std::span<const uint8_t> data) {
  if (data.size() < 3)
    return AppProtocol::kUnknown;

  // HTTP request methods.
  if (StartsWith(data, "GET ") || StartsWith(data, "POST ") || StartsWith(data, "PUT ") ||
      StartsWith(data, "DELETE ") || StartsWith(data, "HEAD ") || StartsWith(data, "OPTIONS ") ||
      StartsWith(data, "PATCH ") || StartsWith(data, "CONNECT ") || StartsWith(data, "TRACE ")) {
    return AppProtocol::kHttp1;
  }

  // HTTP response.
  if (StartsWith(data, "HTTP/")) {
    return AppProtocol::kHttp1;
  }

  // TLS handshake: ContentType=22 (0x16), Version 0x0301-0x0303.
  if (data.size() >= 3 && data[0] == 0x16 && data[1] == 0x03 &&
      (data[2] >= 0x00 && data[2] <= 0x04)) {
    return AppProtocol::kTls;
  }

  // HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
  if (StartsWith(data, "PRI * HTTP/2")) {
    return AppProtocol::kHttp2;
  }

  return AppProtocol::kUnknown;
}

}  // namespace wirepeek::protocol
