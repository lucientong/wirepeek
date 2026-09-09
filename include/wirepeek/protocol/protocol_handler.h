// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file protocol/protocol_handler.h
/// @brief Routes reassembled stream data to appropriate protocol parsers.

#pragma once

#include <wirepeek/app_event.h>
#include <wirepeek/dissector/tcp_reassembler.h>
#include <wirepeek/protocol/http1.h>
#include <wirepeek/protocol/http2.h>
#include <wirepeek/protocol/redis.h>

#include <array>
#include <concepts>
#include <functional>
#include <memory>
#include <span>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace wirepeek::protocol {

/// Manages per-stream protocol detection and parsing.
///
/// Sits between the TcpReassembler and the UI/CLI layer. Receives stream events,
/// detects the application protocol on first data, and routes to the appropriate parser.
class ProtocolHandler {
 public:
  using EventCallback = std::function<void(const ConnectionKey&, const AppEvent&)>;
  using HttpCallback = std::function<void(const ConnectionKey&, const HttpTransaction&)>;
  using RawDataCallback =
      std::function<void(const ConnectionKey&, StreamDirection, std::span<const uint8_t>)>;

  explicit ProtocolHandler(EventCallback callback);
  template <typename Callback>
    requires std::invocable<Callback&, const ConnectionKey&, const AppEvent&>
  explicit ProtocolHandler(Callback callback)
      : ProtocolHandler(EventCallback(std::move(callback))) {}
  ProtocolHandler(HttpCallback http_callback, RawDataCallback raw_callback = nullptr);

  /// Handle a stream event from the TcpReassembler.
  void OnStreamEvent(const dissector::StreamEvent& event, Timestamp ts);

  /// Parse and route a UDP payload, currently including DNS transactions.
  void OnUdpPayload(const ConnectionKey& key, std::span<const uint8_t> payload, Timestamp ts);

 private:
  struct TlsStreamState {
    std::array<std::vector<uint8_t>, 2> buffers;
    std::array<bool, 2> parsed{false, false};
  };

  struct WsStreamState {
    std::array<std::vector<uint8_t>, 2> buffers;
  };

  struct StreamState {
    AppProtocol protocol = AppProtocol::kUnknown;
    bool detected = false;
    bool websocket_upgrade = false;
    bool raw_emitted = false;
    std::optional<std::chrono::microseconds> tcp_handshake;
    std::vector<uint8_t> detection_buffer;
    std::variant<std::monostate, std::unique_ptr<Http1Parser>, std::unique_ptr<Http2Parser>,
                 std::unique_ptr<RedisParser>, TlsStreamState, WsStreamState>
        parser;
  };

  struct PendingDns {
    ConnectionKey key;
    DnsQuery query;
  };

  void Emit(const ConnectionKey& key, AppEvent event) const;
  void FeedTls(const ConnectionKey& key, TlsStreamState& state, std::span<const uint8_t> data,
               StreamDirection direction, Timestamp ts);
  void FeedWebSocket(const ConnectionKey& key, WsStreamState& state, std::span<const uint8_t> data,
                     StreamDirection direction);

  EventCallback callback_;
  std::unordered_map<ConnectionKey, StreamState> streams_;
  std::unordered_map<uint16_t, std::vector<PendingDns>> pending_dns_;
};

}  // namespace wirepeek::protocol
