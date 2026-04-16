// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file analyzer/statistics.h
/// @brief Aggregate traffic statistics and latency analysis.

#pragma once

#include <wirepeek/analyzer/tdigest.h>
#include <wirepeek/packet.h>
#include <wirepeek/request.h>

#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>

namespace wirepeek::analyzer {

/// Point-in-time statistics snapshot.
struct StatsSnapshot {
  int64_t p50_latency_us = 0;    ///< P50 latency in microseconds.
  int64_t p95_latency_us = 0;    ///< P95 latency.
  int64_t p99_latency_us = 0;    ///< P99 latency.
  int64_t avg_latency_us = 0;    ///< Average latency.
  double throughput_mbps = 0.0;  ///< Throughput in Mbps (last 1s window).
  double qps = 0.0;              ///< HTTP transactions per second (last 1s window).
  uint64_t total_requests = 0;   ///< Total HTTP transactions seen.
  uint64_t active_streams = 0;   ///< Currently active TCP streams.
};

/// Thread-safe aggregate statistics collector.
///
/// Collects latency samples via T-Digest and tracks throughput using
/// a sliding time window.
class Statistics {
 public:
  Statistics();

  /// Record a completed HTTP transaction's latency.
  void RecordHttpTransaction(const HttpTransaction& txn);

  /// Record a packet for throughput tracking.
  void RecordPacket(size_t bytes, Timestamp ts);

  /// Record TCP stream lifecycle.
  void RecordStreamOpen();
  void RecordStreamClose();

  /// Get a point-in-time snapshot of all statistics.
  [[nodiscard]] StatsSnapshot Snapshot() const;

  /// Reset all statistics.
  void Reset();

 private:
  mutable std::mutex mutex_;
  TDigest latency_digest_;

  // Throughput: sliding window of (timestamp, bytes) samples.
  struct ByteSample {
    Timestamp ts;
    size_t bytes;
  };
  std::deque<ByteSample> byte_samples_;

  // QPS: sliding window of transaction timestamps.
  std::deque<Timestamp> txn_timestamps_;

  int64_t latency_sum_us_ = 0;
  uint64_t total_requests_ = 0;
  uint64_t active_streams_ = 0;

  static constexpr auto kWindowDuration = std::chrono::seconds(1);

  void PruneOldSamples(Timestamp now);
};

}  // namespace wirepeek::analyzer
