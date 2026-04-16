// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file protocol/dns.h
/// @brief DNS query/response parser.

#pragma once

#include <wirepeek/request.h>

#include <cstdint>
#include <optional>
#include <span>

namespace wirepeek::protocol {

/// Parse a DNS query from a UDP payload.
std::optional<DnsQuery> ParseDnsQuery(std::span<const uint8_t> data);

/// Parse a DNS response from a UDP payload.
std::optional<DnsResponse> ParseDnsResponse(std::span<const uint8_t> data);

/// Check if a UDP payload looks like DNS (port-independent heuristic).
bool LooksDnsShaped(std::span<const uint8_t> data);

}  // namespace wirepeek::protocol
