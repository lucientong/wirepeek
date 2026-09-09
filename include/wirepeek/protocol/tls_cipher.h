// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file protocol/tls_cipher.h
/// @brief Cipher suite metadata for TLS AEAD decryption.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace wirepeek::protocol {

enum class TlsAeadCipher : uint8_t {
  kAes128Gcm,
  kAes256Gcm,
  kChaCha20Poly1305,
};

enum class TlsHash : uint8_t {
  kSha256,
  kSha384,
};

struct TlsCipherSuiteInfo {
  uint16_t id = 0;
  TlsAeadCipher aead = TlsAeadCipher::kAes128Gcm;
  TlsHash hash = TlsHash::kSha256;
  size_t key_len = 16;
  size_t iv_len = 12;
  size_t tag_len = 16;
  size_t hash_len = 32;
  bool tls13_only = false;
  bool tls12_only = false;
  const char* openssl_cipher = "AES-128-GCM";
  const char* openssl_digest = "SHA256";
  const char* name = "TLS_AES_128_GCM_SHA256";
};

[[nodiscard]] std::optional<TlsCipherSuiteInfo> LookupCipherSuite(uint16_t id);

}  // namespace wirepeek::protocol
