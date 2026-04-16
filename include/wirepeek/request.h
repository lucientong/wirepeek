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

// ── HTTP ──────────────────────────────────────────────────────────────────────

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

// ── DNS ───────────────────────────────────────────────────────────────────────

/// DNS query record.
struct DnsQuery {
  uint16_t id = 0;      ///< Transaction ID.
  std::string name;     ///< Query domain name.
  uint16_t type = 0;    ///< Query type (1=A, 28=AAAA, 5=CNAME, etc.).
  Timestamp timestamp;  ///< When the query was seen.
};

/// DNS response record.
struct DnsResponse {
  uint16_t id = 0;                   ///< Transaction ID (matches query).
  std::string name;                  ///< Query domain name.
  uint16_t type = 0;                 ///< Query type.
  uint8_t rcode = 0;                 ///< Response code (0=NoError, 3=NXDomain).
  std::vector<std::string> answers;  ///< Answer strings (IP addresses, CNAMEs).
  Timestamp timestamp;               ///< When the response was seen.
};

/// DNS record type names.
constexpr const char* DnsTypeName(uint16_t type) {
  switch (type) {
    case 1:
      return "A";
    case 2:
      return "NS";
    case 5:
      return "CNAME";
    case 6:
      return "SOA";
    case 15:
      return "MX";
    case 16:
      return "TXT";
    case 28:
      return "AAAA";
    case 33:
      return "SRV";
    case 65:
      return "HTTPS";
    default:
      return "?";
  }
}

// ── TLS ───────────────────────────────────────────────────────────────────────

/// Parsed TLS handshake metadata (no decryption).
struct TlsHandshakeInfo {
  uint16_t version = 0;           ///< TLS version (0x0301=1.0, 0x0303=1.2, 0x0304=1.3).
  std::string sni;                ///< Server Name Indication (from ClientHello extensions).
  std::vector<std::string> alpn;  ///< ALPN protocols (e.g., "h2", "http/1.1").
  std::string cipher_suite;       ///< Selected cipher suite (from ServerHello).
  bool is_client_hello = false;   ///< True if parsed from ClientHello.
  Timestamp timestamp;
};

/// TLS version name.
constexpr const char* TlsVersionName(uint16_t version) {
  switch (version) {
    case 0x0301:
      return "TLS 1.0";
    case 0x0302:
      return "TLS 1.1";
    case 0x0303:
      return "TLS 1.2";
    case 0x0304:
      return "TLS 1.3";
    default:
      return "TLS ?";
  }
}

// ── WebSocket ─────────────────────────────────────────────────────────────────

/// WebSocket frame info.
struct WsFrameInfo {
  uint8_t opcode = 0;      ///< 0=continuation, 1=text, 2=binary, 8=close, 9=ping, 10=pong.
  bool fin = false;        ///< Final fragment flag.
  bool masked = false;     ///< Payload is masked.
  size_t payload_len = 0;  ///< Payload length.
};

/// WebSocket opcode names.
constexpr const char* WsOpcodeName(uint8_t opcode) {
  switch (opcode) {
    case 0:
      return "continuation";
    case 1:
      return "text";
    case 2:
      return "binary";
    case 8:
      return "close";
    case 9:
      return "ping";
    case 10:
      return "pong";
    default:
      return "?";
  }
}

}  // namespace wirepeek
