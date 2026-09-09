// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/tls_cipher.h>

namespace wirepeek::protocol {

std::optional<TlsCipherSuiteInfo> LookupCipherSuite(uint16_t id) {
  switch (id) {
    case 0x1301:  // TLS_AES_128_GCM_SHA256
      return TlsCipherSuiteInfo{0x1301,
                                TlsAeadCipher::kAes128Gcm,
                                TlsHash::kSha256,
                                16,
                                12,
                                16,
                                32,
                                true,
                                false,
                                "AES-128-GCM",
                                "SHA256",
                                "TLS_AES_128_GCM_SHA256"};
    case 0x1302:  // TLS_AES_256_GCM_SHA384
      return TlsCipherSuiteInfo{0x1302,
                                TlsAeadCipher::kAes256Gcm,
                                TlsHash::kSha384,
                                32,
                                12,
                                16,
                                48,
                                true,
                                false,
                                "AES-256-GCM",
                                "SHA384",
                                "TLS_AES_256_GCM_SHA384"};
    case 0x1303:  // TLS_CHACHA20_POLY1305_SHA256
      return TlsCipherSuiteInfo{0x1303,
                                TlsAeadCipher::kChaCha20Poly1305,
                                TlsHash::kSha256,
                                32,
                                12,
                                16,
                                32,
                                true,
                                false,
                                "ChaCha20-Poly1305",
                                "SHA256",
                                "TLS_CHACHA20_POLY1305_SHA256"};
    case 0xC02F:  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
      return TlsCipherSuiteInfo{0xC02F,
                                TlsAeadCipher::kAes128Gcm,
                                TlsHash::kSha256,
                                16,
                                4,
                                16,
                                32,
                                false,
                                true,
                                "AES-128-GCM",
                                "SHA256",
                                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"};
    case 0xC030:  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
      return TlsCipherSuiteInfo{0xC030,
                                TlsAeadCipher::kAes256Gcm,
                                TlsHash::kSha384,
                                32,
                                4,
                                16,
                                48,
                                false,
                                true,
                                "AES-256-GCM",
                                "SHA384",
                                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"};
    case 0xCCA8:  // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
      return TlsCipherSuiteInfo{0xCCA8,
                                TlsAeadCipher::kChaCha20Poly1305,
                                TlsHash::kSha256,
                                32,
                                12,
                                16,
                                32,
                                false,
                                true,
                                "ChaCha20-Poly1305",
                                "SHA256",
                                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"};
    case 0xCCA9:  // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
      return TlsCipherSuiteInfo{0xCCA9,
                                TlsAeadCipher::kChaCha20Poly1305,
                                TlsHash::kSha256,
                                32,
                                12,
                                16,
                                32,
                                false,
                                true,
                                "ChaCha20-Poly1305",
                                "SHA256",
                                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"};
    case 0xC02B:  // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
      return TlsCipherSuiteInfo{0xC02B,
                                TlsAeadCipher::kAes128Gcm,
                                TlsHash::kSha256,
                                16,
                                4,
                                16,
                                32,
                                false,
                                true,
                                "AES-128-GCM",
                                "SHA256",
                                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"};
    case 0xC02C:  // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
      return TlsCipherSuiteInfo{0xC02C,
                                TlsAeadCipher::kAes256Gcm,
                                TlsHash::kSha384,
                                32,
                                4,
                                16,
                                48,
                                false,
                                true,
                                "AES-256-GCM",
                                "SHA384",
                                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"};
    default:
      return std::nullopt;
  }
}

}  // namespace wirepeek::protocol
