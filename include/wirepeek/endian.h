// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file endian.h
/// @brief Inline helpers for reading network byte order (big-endian) values.

#pragma once

#include <cstdint>

namespace wirepeek {

/// Read a 16-bit unsigned integer in big-endian (network) byte order.
inline uint16_t ReadU16Be(const uint8_t* p) {
  return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) << 8 | static_cast<uint16_t>(p[1]));
}

/// Read a 32-bit unsigned integer in big-endian (network) byte order.
inline uint32_t ReadU32Be(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) << 24 | static_cast<uint32_t>(p[1]) << 16 |
         static_cast<uint32_t>(p[2]) << 8 | static_cast<uint32_t>(p[3]);
}

}  // namespace wirepeek
