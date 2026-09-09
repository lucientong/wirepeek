// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file protocol/tls_crypto.h
/// @brief OpenSSL-backed TLS 1.2/1.3 key derivation and AEAD decrypt.

#pragma once

#include <wirepeek/protocol/tls_cipher.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace wirepeek::protocol {

struct TlsTrafficKeys {
  std::vector<uint8_t> key;
  std::vector<uint8_t> iv;
};

enum class TlsDecryptStatus : uint8_t {
  kOk = 0,
  kUnsupported,
  kAuthFailed,
  kInvalidInput,
  kCryptoUnavailable,
};

struct TlsDecryptResult {
  TlsDecryptStatus status = TlsDecryptStatus::kInvalidInput;
  std::vector<uint8_t> plaintext;
};

[[nodiscard]] bool TlsCryptoAvailable();

/// TLS 1.3 HKDF-Expand-Label (RFC 8446).
[[nodiscard]] std::optional<std::vector<uint8_t>> Tls13HkdfExpandLabel(
    TlsHash hash, std::span<const uint8_t> secret, std::string_view label,
    std::span<const uint8_t> context, size_t length);

[[nodiscard]] std::optional<TlsTrafficKeys> Tls13DeriveTrafficKeys(
    const TlsCipherSuiteInfo& suite, std::span<const uint8_t> traffic_secret);

/// TLS 1.3 KeyUpdate: new_secret = HKDF-Expand-Label(old, "traffic upd", "", Hash.length)
[[nodiscard]] std::optional<std::vector<uint8_t>> Tls13UpdateTrafficSecret(
    const TlsCipherSuiteInfo& suite, std::span<const uint8_t> traffic_secret);

/// TLS 1.2 key block from master secret via TLS1-PRF.
[[nodiscard]] std::optional<std::vector<uint8_t>> Tls12PrfKeyBlock(
    const TlsCipherSuiteInfo& suite, std::span<const uint8_t> master_secret,
    std::span<const uint8_t, 32> client_random, std::span<const uint8_t, 32> server_random,
    size_t length);

struct Tls12DirectionKeys {
  std::vector<uint8_t> client_write_key;
  std::vector<uint8_t> server_write_key;
  std::vector<uint8_t> client_write_iv;
  std::vector<uint8_t> server_write_iv;
};

[[nodiscard]] std::optional<Tls12DirectionKeys> Tls12DeriveKeys(
    const TlsCipherSuiteInfo& suite, std::span<const uint8_t> master_secret,
    std::span<const uint8_t, 32> client_random, std::span<const uint8_t, 32> server_random);

/// AEAD decrypt. For AES-GCM TLS 1.2, nonce is implicit_iv || explicit_nonce.
/// For TLS 1.3 / ChaCha, nonce is 12-byte IV XOR padded sequence number.
[[nodiscard]] TlsDecryptResult AeadDecrypt(const TlsCipherSuiteInfo& suite,
                                           std::span<const uint8_t> key,
                                           std::span<const uint8_t> nonce,
                                           std::span<const uint8_t> aad,
                                           std::span<const uint8_t> ciphertext_and_tag);

}  // namespace wirepeek::protocol
