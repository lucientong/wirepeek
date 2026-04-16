// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/analyzer/tdigest.h>

#include <algorithm>
#include <cmath>

namespace wirepeek::analyzer {

TDigest::TDigest(double compression) : compression_(compression) {
  centroids_.reserve(static_cast<size_t>(compression * 3));
}

void TDigest::Add(double value, size_t count) {
  centroids_.push_back({value, count});
  total_count_ += count;
  needs_compress_ = true;

  // Compress periodically to keep centroids bounded.
  if (centroids_.size() > static_cast<size_t>(compression_ * 3)) {
    Compress();
  }
}

void TDigest::Compress() {
  if (centroids_.empty())
    return;

  std::sort(centroids_.begin(), centroids_.end(),
            [](const Centroid& a, const Centroid& b) { return a.mean < b.mean; });

  std::vector<Centroid> merged;
  merged.reserve(static_cast<size_t>(compression_));
  merged.push_back(centroids_[0]);

  for (size_t i = 1; i < centroids_.size(); ++i) {
    auto& last = merged.back();
    size_t new_count = last.count + centroids_[i].count;

    // Calculate the quantile position and allowed size.
    double q = (static_cast<double>(last.count) / 2.0) / static_cast<double>(total_count_);
    double k = 4.0 * total_count_ * q * (1.0 - q) / compression_;
    double max_count = std::max(1.0, k);

    if (static_cast<double>(new_count) <= max_count) {
      // Merge: weighted mean.
      last.mean = (last.mean * static_cast<double>(last.count) +
                   centroids_[i].mean * static_cast<double>(centroids_[i].count)) /
                  static_cast<double>(new_count);
      last.count = new_count;
    } else {
      merged.push_back(centroids_[i]);
    }
  }

  centroids_ = std::move(merged);
  needs_compress_ = false;
}

double TDigest::Quantile(double q) const {
  if (centroids_.empty() || total_count_ == 0)
    return 0.0;
  if (q <= 0.0)
    return centroids_.front().mean;
  if (q >= 1.0)
    return centroids_.back().mean;

  // Need sorted centroids for query.
  auto sorted = centroids_;
  if (needs_compress_) {
    std::sort(sorted.begin(), sorted.end(),
              [](const Centroid& a, const Centroid& b) { return a.mean < b.mean; });
  }

  double target = q * static_cast<double>(total_count_);
  double cumulative = 0.0;

  for (size_t i = 0; i < sorted.size(); ++i) {
    double lower = cumulative;
    double upper = cumulative + static_cast<double>(sorted[i].count);
    double mid = (lower + upper) / 2.0;

    if (target <= mid) {
      if (i == 0)
        return sorted[0].mean;
      // Interpolate between previous and current centroid.
      double prev_mid = cumulative - static_cast<double>(sorted[i - 1].count) / 2.0;
      double frac = (target - prev_mid) / (mid - prev_mid);
      return sorted[i - 1].mean + frac * (sorted[i].mean - sorted[i - 1].mean);
    }
    cumulative = upper;
  }

  return sorted.back().mean;
}

void TDigest::Reset() {
  centroids_.clear();
  total_count_ = 0;
  needs_compress_ = false;
}

}  // namespace wirepeek::analyzer
