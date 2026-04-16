// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file protocol/detector.h
/// @brief Heuristic application-layer protocol detection.

#pragma once

#include <wirepeek/request.h>

#include <cstdint>
#include <span>

namespace wirepeek::protocol {

/// Detect the application-layer protocol from the first bytes of a stream.
///
/// Uses byte-pattern heuristics, not port numbers. Requires at least a few
/// bytes of payload to make a determination.
///
/// @param data First bytes of the stream (typically first kData event).
/// @return Detected protocol, or AppProtocol::kUnknown if unrecognized.
AppProtocol DetectProtocol(std::span<const uint8_t> data);

}  // namespace wirepeek::protocol
