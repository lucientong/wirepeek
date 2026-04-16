// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file protocol/websocket.h
/// @brief WebSocket upgrade detection and frame parsing.

#pragma once

#include <wirepeek/request.h>

#include <cstdint>
#include <optional>
#include <span>

namespace wirepeek::protocol {

/// Check if an HTTP request is a WebSocket upgrade.
bool IsWebSocketUpgrade(const HttpRequest& req);

/// Parse a WebSocket frame header.
std::optional<WsFrameInfo> ParseWsFrame(std::span<const uint8_t> data);

}  // namespace wirepeek::protocol
