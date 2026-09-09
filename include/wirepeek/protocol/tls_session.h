// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file protocol/tls_session.h
/// @brief End-to-end TLS session: framing, decrypt, plaintext callbacks.

#pragma once

#include <wirepeek/protocol/tls_decryptor.h>
#include <wirepeek/protocol/tls_keylog.h>
#include <wirepeek/protocol/tls_record.h>
#include <wirepeek/request.h>
#include <wirepeek/stream.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace wirepeek::protocol {

struct TlsApplicationBytes {
  StreamDirection direction = StreamDirection::kClientToServer;
  std::vector<uint8_t> data;
  Timestamp timestamp;
};

struct TlsSessionResult {
  std::vector<TlsHandshakeInfo> handshakes;
  std::vector<TlsApplicationBytes> application;
  std::optional<std::string> status;  ///< One-shot diagnostic (unknown cipher, auth fail, ...).
};

class TlsSession {
 public:
  explicit TlsSession(std::shared_ptr<TlsKeyLog> keylog);

  TlsSessionResult Feed(std::span<const uint8_t> data, StreamDirection direction, Timestamp ts);

  [[nodiscard]] const TlsHandshakeInfo* ClientHello() const {
    return client_hello_ ? &*client_hello_ : nullptr;
  }
  [[nodiscard]] const TlsHandshakeInfo* ServerHello() const {
    return server_hello_ ? &*server_hello_ : nullptr;
  }
  [[nodiscard]] bool DecryptEnabled() const { return decryptor_.Ready(); }
  [[nodiscard]] const std::string& NegotiatedAlpn() const { return alpn_; }
  [[nodiscard]] std::optional<std::chrono::microseconds> HandshakeDuration() const;

 private:
  void TryInitDecryptor();
  void HandlePlainHandshake(TlsDirection dir, std::span<const uint8_t> payload, Timestamp ts,
                            TlsSessionResult& out);
  void HandlePlaintext(TlsDirection dir, const TlsPlaintextRecord& plain, Timestamp ts,
                       TlsSessionResult& out);

  std::shared_ptr<TlsKeyLog> keylog_;
  std::array<TlsRecordFramer, 2> framers_{};
  std::array<TlsHandshakeReassembler, 2> handshake_reassemblers_{};
  std::optional<TlsHandshakeInfo> client_hello_;
  std::optional<TlsHandshakeInfo> server_hello_;
  std::optional<Timestamp> client_hello_ts_;
  std::optional<Timestamp> handshake_complete_ts_;
  TlsDecryptor decryptor_;
  std::string alpn_;
  bool decrypt_attempted_ = false;
  bool status_emitted_ = false;
  bool unknown_plaintext_emitted_ = false;
};

}  // namespace wirepeek::protocol
