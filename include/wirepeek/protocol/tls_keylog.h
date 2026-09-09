// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace wirepeek::protocol {

/// Secrets belonging to one TLS connection, keyed by ClientHello.random.
struct TlsKeyLogSecrets {
  std::vector<uint8_t> master_secret;  ///< CLIENT_RANDOM (TLS 1.2).
  std::vector<uint8_t> client_handshake_traffic_secret;
  std::vector<uint8_t> server_handshake_traffic_secret;
  std::vector<uint8_t> client_traffic_secret_0;
  std::vector<uint8_t> server_traffic_secret_0;
  /// Additional traffic secret generations after KeyUpdate (index 0 unused).
  std::unordered_map<uint32_t, std::vector<uint8_t>> client_traffic_secret_n;
  std::unordered_map<uint32_t, std::vector<uint8_t>> server_traffic_secret_n;

  void Clear();
};

/// Thread-safe SSLKEYLOGFILE store with optional incremental file tailing.
class TlsKeyLog {
 public:
  ~TlsKeyLog();

  bool Load(const std::string& path, std::string* error = nullptr);
  /// Load newly appended lines since the last successful read. Safe for live capture.
  bool Refresh(std::string* error = nullptr);
  bool ParseLine(std::string_view line);

  [[nodiscard]] size_t SecretCount() const;
  [[nodiscard]] size_t SessionCount() const;

  /// Find a single labeled secret (legacy API).
  [[nodiscard]] const std::vector<uint8_t>* Find(std::string_view label,
                                                 std::string_view client_random_hex) const;

  /// Snapshot secrets for a client_random (hex, lowercase or uppercase).
  [[nodiscard]] std::optional<TlsKeyLogSecrets> Lookup(std::string_view client_random_hex) const;

  /// Bind to a file for subsequent Refresh() calls.
  void SetPath(std::string path);

 private:
  bool LoadFromOffset(std::string* error);
  static bool ApplyLabel(TlsKeyLogSecrets& secrets, std::string_view label,
                         std::vector<uint8_t> value);

  mutable std::mutex mutex_;
  std::unordered_map<std::string, TlsKeyLogSecrets> by_random_;
  std::unordered_map<std::string, std::vector<uint8_t>> secrets_;  ///< label\\nrandom -> bytes
  std::string path_;
  std::uint64_t file_offset_ = 0;
  std::int64_t file_mtime_ns_ = 0;
  std::uint64_t file_size_ = 0;
};

}  // namespace wirepeek::protocol
