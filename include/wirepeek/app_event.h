// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file app_event.h
/// @brief Unified application-layer events emitted by protocol routing.

#pragma once

#include <wirepeek/request.h>
#include <wirepeek/stream.h>

#include <chrono>
#include <cstddef>
#include <optional>
#include <variant>

namespace wirepeek {

struct DnsEvent {
  DnsQuery query;
  std::optional<DnsResponse> response;
  std::chrono::microseconds latency{0};
  bool complete = false;
};

struct WebSocketEvent {
  ConnectionKey key;
  WsFrameInfo frame;
};

struct RawFlowEvent {
  ConnectionKey key;
  StreamDirection dir;
  size_t bytes = 0;
  Timestamp ts;
  AppProtocol protocol = AppProtocol::kUnknown;
};

using AppEvent =
    std::variant<HttpTransaction, RedisTransaction, Http2StreamEvent, DnsEvent, TlsHandshakeInfo,
                 WebSocketEvent, RawFlowEvent>;

}  // namespace wirepeek
