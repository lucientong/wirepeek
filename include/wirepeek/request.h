// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file request.h
/// @brief Application-layer request/response data structures.

#pragma once

#include <wirepeek/packet.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace wirepeek {

/// Detected application-layer protocol.
enum class AppProtocol : uint8_t {
  kUnknown = 0,
  kHttp1,
  kHttp2,
  kTls,
  kDns,
  kWebSocket,
  kGrpc,
  kMysql,
  kRedis,
};

/// Returns a human-readable name for the protocol.
constexpr const char* AppProtocolName(AppProtocol proto) {
  switch (proto) {
    case AppProtocol::kHttp1:
      return "HTTP/1.1";
    case AppProtocol::kHttp2:
      return "HTTP/2";
    case AppProtocol::kTls:
      return "TLS";
    case AppProtocol::kDns:
      return "DNS";
    case AppProtocol::kWebSocket:
      return "WebSocket";
    case AppProtocol::kGrpc:
      return "gRPC";
    case AppProtocol::kMysql:
      return "MySQL";
    case AppProtocol::kRedis:
      return "Redis";
    default:
      return "Unknown";
  }
}

/// HTTP header (name-value pair).
using HttpHeader = std::pair<std::string, std::string>;

/// Parsed HTTP request.
struct HttpRequest {
  std::string method;               ///< HTTP method (GET, POST, etc.).
  std::string url;                  ///< Request URL/path.
  std::string version;              ///< HTTP version (e.g., "HTTP/1.1").
  std::vector<HttpHeader> headers;  ///< Request headers.
  size_t body_size = 0;             ///< Body size in bytes.
  Timestamp timestamp;              ///< When the request was first seen.
};

/// Parsed HTTP response.
struct HttpResponse {
  uint16_t status_code = 0;         ///< HTTP status code (200, 404, etc.).
  std::string reason;               ///< Reason phrase (e.g., "OK", "Not Found").
  std::string version;              ///< HTTP version.
  std::vector<HttpHeader> headers;  ///< Response headers.
  size_t body_size = 0;             ///< Body size in bytes.
  Timestamp timestamp;              ///< When the response was first seen.
};

/// A paired HTTP request and response.
struct HttpTransaction {
  HttpRequest request;
  HttpResponse response;
  std::chrono::microseconds latency{0};  ///< Time from request to first response byte.
  bool complete = false;                 ///< True if both request and response are parsed.
};

}  // namespace wirepeek
