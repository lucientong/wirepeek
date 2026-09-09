// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/analyzer/endpoint_stats.h>

#include <gtest/gtest.h>

using wirepeek::analyzer::EndpointStats;
using wirepeek::analyzer::NormalizeRoute;

TEST(EndpointStatsTest, NormalizesIdsAndDropsQuery) {
  EXPECT_EQ(NormalizeRoute("/users/123/orders/550e8400-e29b-41d4-a716-446655440000?q=x"),
            "/users/:id/orders/:id");
  EXPECT_EQ(NormalizeRoute("/v1/items/abc"), "/v1/items/abc");
}

TEST(EndpointStatsTest, AggregatesAndSortsByCount) {
  EndpointStats stats(2);
  wirepeek::HttpTransaction txn;
  txn.complete = true;
  txn.request.method = "GET";
  txn.request.url = "/users/1";
  txn.response.status_code = 200;
  txn.latency = std::chrono::microseconds(100);
  stats.Record(txn);
  txn.request.url = "/users/2";
  txn.response.status_code = 500;
  txn.latency = std::chrono::microseconds(300);
  stats.Record(txn);

  const auto snapshot = stats.Snapshot();
  ASSERT_EQ(snapshot.size(), 1);
  EXPECT_EQ(snapshot[0].route, "/users/:id");
  EXPECT_EQ(snapshot[0].count, 2);
  EXPECT_EQ(snapshot[0].error_count, 1);
  EXPECT_EQ(snapshot[0].status_class_counts[2], 1);
  EXPECT_EQ(snapshot[0].status_class_counts[5], 1);
  ASSERT_EQ(snapshot[0].slow_requests.size(), 2);
  EXPECT_EQ(snapshot[0].slow_requests[0].latency_us, 300);
}
