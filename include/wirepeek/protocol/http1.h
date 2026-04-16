// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file protocol/http1.h
/// @brief Incremental HTTP/1.1 request/response parser.

#pragma once

#include <wirepeek/packet.h>
#include <wirepeek/request.h>
#include <wirepeek/stream.h>

#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <vector>

namespace wirepeek::protocol {

/// Parser state for one direction of HTTP/1.1 traffic.
enum class Http1ParseState : uint8_t {
  kStartLine,  ///< Waiting for request/status line.
  kHeaders,    ///< Parsing headers.
  kBody,       ///< Reading body (Content-Length based).
  kComplete,   ///< Message fully parsed.
};

/// Incremental HTTP/1.1 parser for a single TCP stream.
///
/// Accumulates bytes from the reassembler, parses request/response pairs,
/// and emits HttpTransactions via a callback. Handles pipelining (multiple
/// request/response pairs on the same connection).
class Http1Parser {
 public:
  using TransactionCallback = std::function<void(const HttpTransaction&)>;

  explicit Http1Parser(TransactionCallback callback);

  /// Feed reassembled stream bytes for one direction.
  void Feed(std::span<const uint8_t> data, StreamDirection dir, Timestamp ts);

  /// Signal that the stream has closed. Emits any pending partial transaction.
  void OnClose();

 private:
  /// Parse accumulated data for one direction.
  void Parse(StreamDirection dir, Timestamp ts);

  /// Try to parse a request start line from the request buffer.
  bool ParseRequestLine();

  /// Try to parse a response status line from the response buffer.
  bool ParseStatusLine();

  /// Try to parse headers from the given buffer.
  bool ParseHeaders(std::string& buffer, std::vector<HttpHeader>& headers, size_t& content_length);

  /// Find CRLF in buffer starting at pos. Returns position of CR, or npos.
  static size_t FindCrlf(const std::string& buffer, size_t pos = 0);

  /// Emit the current transaction and reset for the next one.
  void EmitTransaction();

  TransactionCallback callback_;

  // Per-direction parse state and buffers.
  std::string request_buffer_;
  std::string response_buffer_;
  Http1ParseState request_state_ = Http1ParseState::kStartLine;
  Http1ParseState response_state_ = Http1ParseState::kStartLine;

  // Current transaction being built.
  HttpTransaction current_;
  size_t request_content_length_ = 0;
  size_t response_content_length_ = 0;
  size_t request_body_read_ = 0;
  size_t response_body_read_ = 0;
  bool has_request_ = false;
  bool has_response_ = false;
};

}  // namespace wirepeek::protocol
