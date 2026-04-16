// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file protocol/tls.h
/// @brief TLS handshake metadata parser (ClientHello/ServerHello).

#pragma once

#include <wirepeek/request.h>

#include <cstdint>
#include <optional>
#include <span>

namespace wirepeek::protocol {

/// Parse TLS ClientHello and extract SNI, ALPN, version.
std::optional<TlsHandshakeInfo> ParseTlsClientHello(std::span<const uint8_t> data);

/// Parse TLS ServerHello and extract cipher suite, version.
std::optional<TlsHandshakeInfo> ParseTlsServerHello(std::span<const uint8_t> data);

}  // namespace wirepeek::protocol
