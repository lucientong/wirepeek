// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file protocol/tls_record.h
/// @brief Incremental TLS record framing and handshake message reassembly.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace wirepeek::protocol {

enum class TlsContentType : uint8_t {
  kChangeCipherSpec = 20,
  kAlert = 21,
  kHandshake = 22,
  kApplicationData = 23,
};

enum class TlsHandshakeType : uint8_t {
  kClientHello = 1,
  kServerHello = 2,
  kNewSessionTicket = 4,
  kEndOfEarlyData = 5,
  kEncryptedExtensions = 8,
  kCertificate = 11,
  kCertificateRequest = 13,
  kCertificateVerify = 15,
  kFinished = 20,
  kKeyUpdate = 24,
  kMessageHash = 254,
};

struct TlsRecord {
  TlsContentType type = TlsContentType::kHandshake;
  uint16_t version = 0;
  std::vector<uint8_t> payload;
};

struct TlsHandshakeMessage {
  TlsHandshakeType type = TlsHandshakeType::kClientHello;
  std::vector<uint8_t> body;  ///< Handshake body only (without type/length header).
};

/// Per-direction TLS record framer. Handles partial TCP segments and multi-record buffers.
class TlsRecordFramer {
 public:
  static constexpr size_t kHeaderLen = 5;
  static constexpr size_t kMaxRecordPayload = 16384 + 256;  // TLS 1.3 ciphertext ceiling.
  static constexpr size_t kMaxBuffer = 2 * 1024 * 1024;

  /// Feed bytes; returns newly completed records (may be empty).
  std::vector<TlsRecord> Feed(std::span<const uint8_t> data);

  [[nodiscard]] bool Failed() const { return failed_; }
  [[nodiscard]] size_t PendingBytes() const { return buffer_.size(); }
  void Reset();

 private:
  std::vector<uint8_t> buffer_;
  bool failed_ = false;
};

/// Reassembles handshake messages that may span multiple TLS records.
class TlsHandshakeReassembler {
 public:
  static constexpr size_t kMaxMessage = 64 * 1024;

  std::vector<TlsHandshakeMessage> Feed(std::span<const uint8_t> handshake_payload);
  [[nodiscard]] bool Failed() const { return failed_; }
  void Reset();

 private:
  std::vector<uint8_t> buffer_;
  bool failed_ = false;
};

}  // namespace wirepeek::protocol
