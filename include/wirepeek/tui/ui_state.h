// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file tui/ui_state.h
/// @brief Thread-safe shared state between capture thread and UI thread.

#pragma once

#include <wirepeek/packet.h>

#include <algorithm>
#include <cctype>
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
  // Latency percentiles (microseconds).
  int64_t p50_latency_us = 0;
  int64_t p95_latency_us = 0;
  int64_t p99_latency_us = 0;
  // Throughput.
  double throughput_mbps = 0.0;
  double qps = 0.0;
  // Sparkline: last N seconds of packet counts for the traffic chart.
  std::vector<int> pps_history;  ///< Packets-per-second over the last 60 seconds.
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

  void UpdateAnalyzerStats(int64_t p50, int64_t p95, int64_t p99, double mbps, double qps) {
    std::lock_guard lock(mutex_);
    stats_.p50_latency_us = p50;
    stats_.p95_latency_us = p95;
    stats_.p99_latency_us = p99;
    stats_.throughput_mbps = mbps;
    stats_.qps = qps;
  }

  /// Push a packets-per-second sample for the sparkline chart.
  void PushPpsSample(int pps) {
    std::lock_guard lock(mutex_);
    pps_history_.push_back(pps);
    if (pps_history_.size() > kSparklineLen) {
      pps_history_.pop_front();
    }
  }

  TuiStats GetStats() const {
    std::lock_guard lock(mutex_);
    auto s = stats_;
    s.pps_history = {pps_history_.begin(), pps_history_.end()};
    return s;
  }

  /// Get entries matching a filter string (case-insensitive substring match on
  /// protocol/method/url).
  std::vector<TuiEntry> GetFilteredEntries(const std::string& filter) const {
    std::lock_guard lock(mutex_);
    if (filter.empty())
      return {entries_.begin(), entries_.end()};
    std::vector<TuiEntry> result;
    for (const auto& e : entries_) {
      if (ContainsCI(e.protocol, filter) || ContainsCI(e.method, filter) ||
          ContainsCI(e.url, filter)) {
        result.push_back(e);
      }
    }
    return result;
  }

 private:
  static constexpr size_t kSparklineLen = 60;

  static bool ContainsCI(const std::string& haystack, const std::string& needle) {
    if (needle.empty())
      return true;
    auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                          [](char a, char b) { return std::tolower(a) == std::tolower(b); });
    return it != haystack.end();
  }

  mutable std::mutex mutex_;
  std::deque<TuiEntry> entries_;
  TuiStats stats_;
  std::deque<int> pps_history_;
};

}  // namespace wirepeek::tui
