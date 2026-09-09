// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file protocol/tls_decryptor.h
/// @brief Per-direction TLS record decryptor (fail-closed on auth failure).

#pragma once

#include <wirepeek/protocol/tls_cipher.h>
#include <wirepeek/protocol/tls_crypto.h>
#include <wirepeek/protocol/tls_keylog.h>
#include <wirepeek/protocol/tls_record.h>
#include <wirepeek/request.h>

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace wirepeek::protocol {

enum class TlsDirection : uint8_t {
  kClient = 0,
  kServer = 1,
};

struct TlsPlaintextRecord {
  TlsContentType type = TlsContentType::kApplicationData;
  std::vector<uint8_t> data;
};

class TlsDirectionDecryptor {
 public:
  void ConfigureTls13(const TlsCipherSuiteInfo& suite, std::vector<uint8_t> traffic_secret);
  void ConfigureTls12(const TlsCipherSuiteInfo& suite, std::vector<uint8_t> write_key,
                      std::vector<uint8_t> write_iv);

  bool UpdateTrafficSecret();

  [[nodiscard]] std::optional<TlsPlaintextRecord> Decrypt(const TlsRecord& record);
  [[nodiscard]] bool Abandoned() const { return abandoned_; }
  [[nodiscard]] bool Ready() const { return ready_; }
  [[nodiscard]] uint64_t Sequence() const { return sequence_; }

  void Abandon();
  void ResetSequence() { sequence_ = 0; }

 private:
  std::array<uint8_t, 12> BuildNonce(std::span<const uint8_t> explicit_nonce) const;

  TlsCipherSuiteInfo suite_{};
  std::vector<uint8_t> traffic_secret_;
  std::vector<uint8_t> key_;
  std::vector<uint8_t> iv_;
  uint64_t sequence_ = 0;
  bool tls13_ = false;
  bool ready_ = false;
  bool abandoned_ = false;
  int consecutive_failures_ = 0;
  static constexpr int kMaxFailures = 8;
};

/// Manages handshake/application epochs and CCS gating.
class TlsDecryptor {
 public:
  bool InitializeFromHandshake(const TlsHandshakeInfo& client_hello,
                               const TlsHandshakeInfo& server_hello,
                               const TlsKeyLogSecrets& secrets);

  void OnChangeCipherSpec(TlsDirection dir);
  bool OnKeyUpdate(TlsDirection dir, std::span<const uint8_t> body);

  [[nodiscard]] std::optional<TlsPlaintextRecord> DecryptRecord(TlsDirection dir,
                                                                const TlsRecord& record);

  [[nodiscard]] bool IsTls13() const { return tls13_; }
  [[nodiscard]] bool Ready() const { return ready_; }
  [[nodiscard]] const TlsCipherSuiteInfo& Suite() const { return suite_; }
  [[nodiscard]] bool DirectionAbandoned(TlsDirection dir) const;

 private:
  void MaybePromoteToApplication(TlsDirection dir, const TlsPlaintextRecord& plain);

  TlsCipherSuiteInfo suite_{};
  TlsDirectionDecryptor client_hs_;
  TlsDirectionDecryptor server_hs_;
  TlsDirectionDecryptor client_app_;
  TlsDirectionDecryptor server_app_;
  bool tls13_ = false;
  bool ready_ = false;
  bool client_ccs_ = false;
  bool server_ccs_ = false;
  bool client_app_active_ = false;
  bool server_app_active_ = false;
  bool have_app_secrets_ = false;
};

}  // namespace wirepeek::protocol
