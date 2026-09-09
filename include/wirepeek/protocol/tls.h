// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file protocol/tls.h
/// @brief TLS handshake metadata parser (ClientHello/ServerHello).

#pragma once

#include <wirepeek/request.h>

#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace wirepeek::protocol {

/// Format 32-byte random as lowercase hex (64 chars) for SSLKEYLOGFILE lookup.
std::string HexEncode(std::span<const uint8_t> bytes);

/// Parse TLS ClientHello from a full TLS record (ContentType=Handshake).
std::optional<TlsHandshakeInfo> ParseTlsClientHello(std::span<const uint8_t> data);

/// Parse TLS ServerHello from a full TLS record (ContentType=Handshake).
std::optional<TlsHandshakeInfo> ParseTlsServerHello(std::span<const uint8_t> data);

/// Parse ClientHello handshake body (after HandshakeType+Length).
std::optional<TlsHandshakeInfo> ParseTlsClientHelloBody(std::span<const uint8_t> body);

/// Parse ServerHello handshake body (after HandshakeType+Length).
std::optional<TlsHandshakeInfo> ParseTlsServerHelloBody(std::span<const uint8_t> body);

}  // namespace wirepeek::protocol
