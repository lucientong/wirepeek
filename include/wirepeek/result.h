// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file result.h
/// @brief Error handling types for protocol dissection.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

// Use std::expected if available (C++23), otherwise provide a minimal fallback.
#if __has_include(<expected>) && __cplusplus >= 202302L
#include <expected>
#else
#include <variant>
#endif

namespace wirepeek {

/// Error codes returned by protocol dissectors.
enum class DissectError : uint8_t {
  kTruncated,           ///< Packet data too short for the expected header.
  kInvalidHeader,       ///< Header fields contain invalid values.
  kUnsupportedVersion,  ///< Protocol version not supported.
  kChecksumError,       ///< Header checksum verification failed.
};

/// Returns a human-readable string for a DissectError.
constexpr std::string_view DissectErrorToString(DissectError err) {
  switch (err) {
    case DissectError::kTruncated:
      return "truncated packet";
    case DissectError::kInvalidHeader:
      return "invalid header";
    case DissectError::kUnsupportedVersion:
      return "unsupported version";
    case DissectError::kChecksumError:
      return "checksum error";
  }
  return "unknown error";
}

// Provide DissectResult<T> as std::expected<T, DissectError> or a minimal fallback.
#if __has_include(<expected>) && __cplusplus >= 202302L

template <typename T>
using DissectResult = std::expected<T, DissectError>;

#else

/// Minimal expected-like type for compilers without C++23 <expected>.
template <typename T>
class DissectResult {
 public:
  // NOLINTNEXTLINE(google-explicit-constructor)
  DissectResult(T value) : data_(std::move(value)) {}

  // NOLINTNEXTLINE(google-explicit-constructor)
  DissectResult(DissectError error) : data_(error) {}

  [[nodiscard]] bool has_value() const { return std::holds_alternative<T>(data_); }
  explicit operator bool() const { return has_value(); }

  T& value() { return std::get<T>(data_); }
  const T& value() const { return std::get<T>(data_); }

  T& operator*() { return value(); }
  const T& operator*() const { return value(); }

  T* operator->() { return &value(); }
  const T* operator->() const { return &value(); }

  DissectError error() const { return std::get<DissectError>(data_); }

  template <typename F>
  auto and_then(F&& f) const -> decltype(f(std::declval<const T&>())) {
    if (has_value()) return f(value());
    return DissectResult<typename decltype(f(std::declval<const T&>()))::value_type>(error());
  }

 private:
  std::variant<T, DissectError> data_;
};

/// Helper to construct an error result.
template <typename T>
DissectResult<T> MakeDissectError(DissectError err) {
  return DissectResult<T>(err);
}

#endif

/// Helper: create an unexpected error (works with both std::expected and fallback).
template <typename T>
DissectResult<T> Unexpected(DissectError err) {
#if __has_include(<expected>) && __cplusplus >= 202302L
  return std::unexpected(err);
#else
  return DissectResult<T>(err);
#endif
}

}  // namespace wirepeek
