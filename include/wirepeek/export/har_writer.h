// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file export/har_writer.h
/// @brief Export HTTP transactions to HAR (HTTP Archive) format.

#pragma once

#include <wirepeek/request.h>

#include <string>
#include <vector>

namespace wirepeek::exporter {

/// Collects HTTP transactions and writes them as a HAR 1.2 JSON file.
class HarWriter {
 public:
  /// Add a transaction to the collection.
  void AddTransaction(const HttpTransaction& txn);

  /// Write all collected transactions to a HAR file.
  /// @throws std::runtime_error if file cannot be written.
  void WriteToFile(const std::string& path) const;

  /// Serialize to HAR JSON string.
  [[nodiscard]] std::string ToJson() const;

  [[nodiscard]] size_t TransactionCount() const { return transactions_.size(); }

 private:
  std::vector<HttpTransaction> transactions_;
};

}  // namespace wirepeek::exporter
