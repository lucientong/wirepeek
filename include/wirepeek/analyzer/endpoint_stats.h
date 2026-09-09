// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <wirepeek/analyzer/tdigest.h>
#include <wirepeek/request.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace wirepeek::analyzer {

struct SlowRequest {
  int64_t latency_us = 0;
  uint16_t status = 0;
  Timestamp timestamp;
};

struct EndpointSnapshot {
  std::string method;
  std::string route;
  uint64_t count = 0;
  uint64_t error_count = 0;
  std::array<uint64_t, 6> status_class_counts{};
  int64_t p50_latency_us = 0;
  int64_t p95_latency_us = 0;
  int64_t p99_latency_us = 0;
  std::vector<SlowRequest> slow_requests;
};

std::string NormalizeRoute(std::string_view path);

class EndpointStats {
 public:
  explicit EndpointStats(size_t slow_top_n = 0) : slow_top_n_(slow_top_n) {}

  void Record(const HttpTransaction& transaction);
  [[nodiscard]] std::vector<EndpointSnapshot> Snapshot() const;
  void Reset();

 private:
  struct Aggregate {
    explicit Aggregate() : latencies(100.0) {}
    std::string method;
    std::string route;
    uint64_t count = 0;
    uint64_t error_count = 0;
    std::array<uint64_t, 6> status_class_counts{};
    TDigest latencies;
    std::vector<SlowRequest> slow_requests;
  };

  mutable std::mutex mutex_;
  std::unordered_map<std::string, Aggregate> endpoints_;
  size_t slow_top_n_;
};

}  // namespace wirepeek::analyzer
