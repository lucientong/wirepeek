// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file protocol/http1.h
/// @brief Incremental HTTP/1.1 request/response parser.

#pragma once

#include <wirepeek/packet.h>
#include <wirepeek/request.h>
#include <wirepeek/stream.h>

#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace wirepeek::protocol {

/// Parser state for one direction of HTTP/1.1 traffic.
enum class Http1ParseState : uint8_t {
  kStartLine,  ///< Waiting for request/status line.
  kHeaders,    ///< Parsing headers.
  kBody,       ///< Reading body according to the selected body mode.
  kComplete,   ///< Message fully parsed.
};

enum class Http1BodyMode : uint8_t {
  kNone,
  kContentLength,
  kChunked,
  kUntilClose,
};

/// Incremental HTTP/1.1 parser for a single TCP stream.
///
/// Accumulates bytes from the reassembler, parses request/response pairs,
/// and emits HttpTransactions via a callback. Handles pipelining (multiple
/// request/response pairs on the same connection).
class Http1Parser {
 public:
  using TransactionCallback = std::function<void(const HttpTransaction&)>;
  using UpgradeCallback = std::function<void()>;

  explicit Http1Parser(TransactionCallback callback, UpgradeCallback upgrade_callback = {});

  /// Feed reassembled stream bytes for one direction.
  void Feed(std::span<const uint8_t> data, StreamDirection dir, Timestamp ts);

  /// Signal that the stream has closed. Emits any pending partial transaction.
  void OnClose();

  [[nodiscard]] bool IsUpgraded() const { return upgraded_; }

 private:
  struct MessageState {
    Http1ParseState state = Http1ParseState::kStartLine;
    Http1BodyMode body_mode = Http1BodyMode::kNone;
    size_t content_length = 0;
    size_t body_read = 0;
    size_t message_bytes = 0;
    size_t chunk_remaining = 0;
    bool reading_trailers = false;
    Timestamp timestamp{};

    void Reset();
  };

  struct HeaderInfo {
    std::optional<size_t> content_length;
    bool chunked = false;
  };

  void ParseRequests(Timestamp ts);
  void ParseResponses(Timestamp ts);
  bool ParseRequestLine();
  bool ParseStatusLine();
  bool ParseHeaders(std::string& buffer, std::vector<HttpHeader>& headers, HeaderInfo& info,
                    MessageState& state);
  bool ConsumeBody(std::string& buffer, MessageState& state, size_t& body_size);
  bool ConsumeChunked(std::string& buffer, MessageState& state, size_t& body_size);
  void CompleteRequest();
  void CompleteResponse();
  void EmitPair(HttpRequest request, HttpResponse response, bool complete);
  void ResetRequest();
  void ResetResponse();
  void FailDirection(std::string& buffer, MessageState& state);

  static bool HeaderContainsToken(const std::vector<HttpHeader>& headers, std::string_view name,
                                  std::string_view token);
  static bool IsNoBodyResponse(uint16_t status, std::string_view request_method);
  static size_t FindCrlf(const std::string& buffer, size_t pos = 0);

  TransactionCallback callback_;
  UpgradeCallback upgrade_callback_;

  std::string request_buffer_;
  std::string response_buffer_;
  MessageState request_state_;
  MessageState response_state_;
  HttpRequest current_request_;
  HttpResponse current_response_;
  Timestamp response_completion_timestamp_{};
  std::deque<HttpRequest> pending_requests_;
  bool upgraded_ = false;

  static constexpr size_t kMaxStartLineBytes = 8 * 1024;
  static constexpr size_t kMaxHeaderBytes = 64 * 1024;
  static constexpr size_t kMaxBodyBytes = 64 * 1024 * 1024;
  static constexpr size_t kMaxMessageBytes = kMaxHeaderBytes + kMaxBodyBytes;
};

}  // namespace wirepeek::protocol
