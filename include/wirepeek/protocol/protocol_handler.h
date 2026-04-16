// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file protocol/protocol_handler.h
/// @brief Routes reassembled stream data to appropriate protocol parsers.

#pragma once

#include <wirepeek/dissector/tcp_reassembler.h>
#include <wirepeek/protocol/http1.h>
#include <wirepeek/request.h>
#include <wirepeek/stream.h>

#include <functional>
#include <memory>
#include <unordered_map>

namespace wirepeek::protocol {

/// Manages per-stream protocol detection and parsing.
///
/// Sits between the TcpReassembler and the UI/CLI layer. Receives stream events,
/// detects the application protocol on first data, and routes to the appropriate parser.
class ProtocolHandler {
 public:
  using HttpCallback = std::function<void(const ConnectionKey&, const HttpTransaction&)>;
  using RawDataCallback =
      std::function<void(const ConnectionKey&, StreamDirection, std::span<const uint8_t>)>;

  /// @param http_cb Called when an HTTP transaction is parsed.
  /// @param raw_cb Called for non-HTTP stream data (fallback).
  ProtocolHandler(HttpCallback http_cb, RawDataCallback raw_cb = nullptr);

  /// Handle a stream event from the TcpReassembler.
  void OnStreamEvent(const dissector::StreamEvent& event, Timestamp ts);

 private:
  struct StreamState {
    AppProtocol protocol = AppProtocol::kUnknown;
    bool detected = false;
    std::unique_ptr<Http1Parser> http_parser;
  };

  HttpCallback http_callback_;
  RawDataCallback raw_callback_;
  std::unordered_map<ConnectionKey, StreamState> streams_;
};

}  // namespace wirepeek::protocol
