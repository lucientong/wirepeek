// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/analyzer/statistics.h>

#include <algorithm>

namespace wirepeek::analyzer {

Statistics::Statistics() : latency_digest_(100.0) {}

void Statistics::RecordHttpTransaction(const HttpTransaction& txn) {
  if (!txn.complete)
    return;

  std::lock_guard lock(mutex_);
  auto us = txn.latency.count();
  latency_digest_.Add(static_cast<double>(us));
  latency_sum_us_ += us;
  ++total_requests_;

  txn_timestamps_.push_back(txn.response.timestamp);
  last_sample_time_ = txn.response.timestamp;
  PruneOldSamples(txn.response.timestamp);
}

void Statistics::RecordPacket(size_t bytes, Timestamp ts) {
  std::lock_guard lock(mutex_);
  ++total_packets_;
  byte_samples_.push_back({ts, bytes});
  window_bytes_ += bytes;
  last_sample_time_ = ts;
  PruneOldSamples(ts);
}

void Statistics::RecordStreamOpen() {
  std::lock_guard lock(mutex_);
  ++active_streams_;
}

void Statistics::RecordStreamClose() {
  std::lock_guard lock(mutex_);
  if (active_streams_ > 0)
    --active_streams_;
}

void Statistics::PruneOldSamples(Timestamp now) {
  auto cutoff = now - kWindowDuration;

  while (!byte_samples_.empty() && byte_samples_.front().ts < cutoff) {
    window_bytes_ -= byte_samples_.front().bytes;
    byte_samples_.pop_front();
  }
  while (!txn_timestamps_.empty() && txn_timestamps_.front() < cutoff) {
    txn_timestamps_.pop_front();
  }
}

StatsSnapshot Statistics::Snapshot(std::optional<Timestamp> now) {
  std::lock_guard lock(mutex_);
  if (now) {
    PruneOldSamples(*now);
  } else if (last_sample_time_) {
    PruneOldSamples(*last_sample_time_);
  }

  StatsSnapshot snap;
  snap.total_requests = total_requests_;
  snap.total_packets = total_packets_;
  snap.active_streams = active_streams_;

  if (latency_digest_.Count() > 0) {
    snap.p50_latency_us = static_cast<int64_t>(latency_digest_.Quantile(0.50));
    snap.p95_latency_us = static_cast<int64_t>(latency_digest_.Quantile(0.95));
    snap.p99_latency_us = static_cast<int64_t>(latency_digest_.Quantile(0.99));
    if (total_requests_ > 0) {
      snap.avg_latency_us = latency_sum_us_ / static_cast<int64_t>(total_requests_);
    }
  }

  const double window_seconds = std::chrono::duration<double>(kWindowDuration).count();
  snap.throughput_mbps = static_cast<double>(window_bytes_) * 8.0 / window_seconds / 1'000'000.0;

  snap.qps = static_cast<double>(txn_timestamps_.size()) / window_seconds;

  return snap;
}

void Statistics::Reset() {
  std::lock_guard lock(mutex_);
  latency_digest_.Reset();
  byte_samples_.clear();
  window_bytes_ = 0;
  txn_timestamps_.clear();
  last_sample_time_.reset();
  latency_sum_us_ = 0;
  total_requests_ = 0;
  total_packets_ = 0;
  active_streams_ = 0;
}

}  // namespace wirepeek::analyzer
