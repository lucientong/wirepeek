// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file analyzer/tdigest.h
/// @brief Streaming percentile estimation using a simplified T-Digest algorithm.

#pragma once

#include <cstddef>
#include <vector>

namespace wirepeek::analyzer {

/// Simplified T-Digest for streaming percentile estimation.
///
/// Maintains a sorted list of centroids that approximate the distribution.
/// Accuracy is ~1% for extreme percentiles (P95/P99) with ~200 centroids.
class TDigest {
 public:
  /// @param compression Controls accuracy vs memory. Higher = more centroids = more accurate.
  explicit TDigest(double compression = 100.0);

  /// Add a value to the digest.
  void Add(double value, size_t count = 1);

  /// Query a percentile. q is in [0.0, 1.0] (e.g., 0.95 for P95).
  /// Returns 0.0 if empty.
  [[nodiscard]] double Quantile(double q) const;

  /// Number of values added.
  [[nodiscard]] size_t Count() const { return total_count_; }

  /// Reset to empty state.
  void Reset();

 private:
  struct Centroid {
    double mean = 0.0;
    size_t count = 0;
  };

  void Compress();

  double compression_;
  std::vector<Centroid> centroids_;
  size_t total_count_ = 0;
  bool needs_compress_ = false;
};

}  // namespace wirepeek::analyzer
