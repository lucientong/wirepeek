// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file tui/ui_state.h
/// @brief Thread-safe shared state between capture thread and UI thread.

#pragma once

#include <wirepeek/packet.h>

#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace wirepeek::tui {

/// One row in the TUI request table.
struct TuiEntry {
  Timestamp timestamp;
  std::string protocol;  ///< "HTTP", "TLS", "TCP", "UDP", etc.
  std::string method;    ///< "GET", "POST", etc. (empty for non-HTTP).
  std::string url;       ///< URL or endpoint description.
  uint16_t status = 0;   ///< HTTP status code (0 if non-HTTP).
  std::string latency;   ///< Formatted latency string (e.g., "43ms").
  std::string size;      ///< Formatted size string.
  std::string detail;    ///< Multi-line detail text (headers, body preview).
};

/// Aggregate statistics for the stats bar.
struct TuiStats {
  uint64_t packet_count = 0;
  uint64_t stream_count = 0;
  uint64_t http_txn_count = 0;
  uint64_t total_bytes = 0;
};

/// Thread-safe shared state. Capture thread writes, UI thread reads.
class UiState {
 public:
  static constexpr size_t kMaxEntries = 10000;

  /// Add an entry (called from capture thread).
  void AddEntry(TuiEntry entry) {
    std::lock_guard lock(mutex_);
    entries_.push_back(std::move(entry));
    if (entries_.size() > kMaxEntries) {
      entries_.pop_front();
    }
  }

  /// Get a snapshot of entries (called from UI thread).
  std::vector<TuiEntry> GetEntries() const {
    std::lock_guard lock(mutex_);
    return {entries_.begin(), entries_.end()};
  }

  /// Get entry count without copying.
  size_t EntryCount() const {
    std::lock_guard lock(mutex_);
    return entries_.size();
  }

  /// Increment packet count.
  void IncrementPackets(uint64_t bytes = 0) {
    std::lock_guard lock(mutex_);
    ++stats_.packet_count;
    stats_.total_bytes += bytes;
  }

  void SetStreamCount(uint64_t count) {
    std::lock_guard lock(mutex_);
    stats_.stream_count = count;
  }

  void IncrementHttpTransactions() {
    std::lock_guard lock(mutex_);
    ++stats_.http_txn_count;
  }

  TuiStats GetStats() const {
    std::lock_guard lock(mutex_);
    return stats_;
  }

 private:
  mutable std::mutex mutex_;
  std::deque<TuiEntry> entries_;
  TuiStats stats_;
};

}  // namespace wirepeek::tui
