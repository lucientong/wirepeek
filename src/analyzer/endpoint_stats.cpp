// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/analyzer/endpoint_stats.h>

#include <algorithm>
#include <cctype>
#include <string_view>

namespace wirepeek::analyzer {
namespace {

bool IsNumeric(std::string_view segment) {
  return !segment.empty() &&
         std::all_of(segment.begin(), segment.end(),
                     [](unsigned char c) { return std::isdigit(c); });
}

bool IsUuid(std::string_view segment) {
  if (segment.size() != 36)
    return false;
  for (size_t i = 0; i < segment.size(); ++i) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (segment[i] != '-')
        return false;
    } else if (!std::isxdigit(static_cast<unsigned char>(segment[i]))) {
      return false;
    }
  }
  return true;
}

}  // namespace

std::string NormalizeRoute(std::string_view path) {
  if (const auto query = path.find('?'); query != std::string_view::npos)
    path = path.substr(0, query);
  if (path.empty())
    return "/";

  std::string result;
  size_t pos = 0;
  while (pos < path.size()) {
    const auto slash = path.find('/', pos);
    const auto end = slash == std::string_view::npos ? path.size() : slash;
    const auto segment = path.substr(pos, end - pos);
    result += (IsNumeric(segment) || IsUuid(segment)) ? ":id" : std::string(segment);
    if (slash == std::string_view::npos)
      break;
    result.push_back('/');
    pos = slash + 1;
  }
  return result.empty() ? "/" : result;
}

void EndpointStats::Record(const HttpTransaction& transaction) {
  if (!transaction.complete || transaction.request.method.empty())
    return;

  const std::string route = NormalizeRoute(transaction.request.url);
  const std::string key = transaction.request.method + '\n' + route;
  std::lock_guard lock(mutex_);
  auto [it, inserted] = endpoints_.try_emplace(key);
  auto& aggregate = it->second;
  if (inserted) {
    aggregate.method = transaction.request.method;
    aggregate.route = route;
  }
  ++aggregate.count;
  if (transaction.response.status_code >= 400)
    ++aggregate.error_count;
  const size_t status_class = std::min<size_t>(transaction.response.status_code / 100, 5);
  ++aggregate.status_class_counts[status_class];
  aggregate.latencies.Add(static_cast<double>(transaction.latency.count()));

  if (slow_top_n_ > 0) {
    aggregate.slow_requests.push_back(
        {.latency_us = transaction.latency.count(),
         .status = transaction.response.status_code,
         .timestamp = transaction.request.timestamp});
    std::sort(aggregate.slow_requests.begin(), aggregate.slow_requests.end(),
              [](const SlowRequest& a, const SlowRequest& b) {
                return a.latency_us > b.latency_us;
              });
    if (aggregate.slow_requests.size() > slow_top_n_)
      aggregate.slow_requests.resize(slow_top_n_);
  }
}

std::vector<EndpointSnapshot> EndpointStats::Snapshot() const {
  std::lock_guard lock(mutex_);
  std::vector<EndpointSnapshot> result;
  result.reserve(endpoints_.size());
  for (const auto& [_, aggregate] : endpoints_) {
    EndpointSnapshot snapshot{
        .method = aggregate.method,
        .route = aggregate.route,
        .count = aggregate.count,
        .error_count = aggregate.error_count,
        .status_class_counts = aggregate.status_class_counts,
        .slow_requests = aggregate.slow_requests,
    };
    if (aggregate.latencies.Count() > 0) {
      snapshot.p50_latency_us = static_cast<int64_t>(aggregate.latencies.Quantile(0.50));
      snapshot.p95_latency_us = static_cast<int64_t>(aggregate.latencies.Quantile(0.95));
      snapshot.p99_latency_us = static_cast<int64_t>(aggregate.latencies.Quantile(0.99));
    }
    result.push_back(std::move(snapshot));
  }
  std::sort(result.begin(), result.end(), [](const EndpointSnapshot& a, const EndpointSnapshot& b) {
    if (a.count != b.count)
      return a.count > b.count;
    return std::tie(a.method, a.route) < std::tie(b.method, b.route);
  });
  return result;
}

void EndpointStats::Reset() {
  std::lock_guard lock(mutex_);
  endpoints_.clear();
}

}  // namespace wirepeek::analyzer
