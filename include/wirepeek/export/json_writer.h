// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file export/json_writer.h
/// @brief Export captured data as newline-delimited JSON (NDJSON).

#pragma once

#include <wirepeek/dissector/dissect.h>
#include <wirepeek/packet.h>
#include <wirepeek/request.h>

#include <cstdint>
#include <string>

namespace wirepeek::exporter {

/// Writes packets and HTTP transactions as NDJSON (one JSON object per line).
/// Suitable for piping to jq, log aggregation systems, or CI integration.
class JsonWriter {
 public:
  /// Open a file for NDJSON output. Use "-" for stdout.
  explicit JsonWriter(const std::string& path);
  ~JsonWriter();

  JsonWriter(const JsonWriter&) = delete;
  JsonWriter& operator=(const JsonWriter&) = delete;

  /// Write a raw packet summary as JSON.
  void WritePacket(const wirepeek::PacketView& pkt,
                   const wirepeek::dissector::DissectedPacket& dissected);

  /// Write an HTTP transaction as JSON.
  void WriteHttpTransaction(const HttpTransaction& txn);

  /// Number of lines written.
  [[nodiscard]] uint64_t LineCount() const { return count_; }

  void Close();

 private:
  void Write(const std::string& line);

  std::string path_;
  int fd_ = -1;
  bool is_stdout_ = false;
  uint64_t count_ = 0;
};

}  // namespace wirepeek::exporter
