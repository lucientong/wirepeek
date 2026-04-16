// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/analyzer/statistics.h>

#include <chrono>
#include <gtest/gtest.h>

namespace wirepeek::analyzer {
namespace {

wirepeek::Timestamp MakeTs(int seconds) {
  return wirepeek::Timestamp(std::chrono::seconds(seconds));
}

TEST(StatisticsTest, EmptySnapshot) {
  Statistics stats;
  auto snap = stats.Snapshot();
  EXPECT_EQ(snap.p50_latency_us, 0);
  EXPECT_EQ(snap.total_requests, 0u);
  EXPECT_DOUBLE_EQ(snap.throughput_mbps, 0.0);
}

TEST(StatisticsTest, RecordHttpTransaction) {
  Statistics stats;

  wirepeek::HttpTransaction txn;
  txn.complete = true;
  txn.latency = std::chrono::microseconds(5000);  // 5ms
  txn.request.timestamp = MakeTs(1);
  txn.response.timestamp = MakeTs(1);

  stats.RecordHttpTransaction(txn);

  auto snap = stats.Snapshot();
  EXPECT_EQ(snap.total_requests, 1u);
  EXPECT_EQ(snap.p50_latency_us, 5000);
}

TEST(StatisticsTest, LatencyPercentiles) {
  Statistics stats;

  // Add transactions with increasing latency.
  for (int i = 1; i <= 100; ++i) {
    wirepeek::HttpTransaction txn;
    txn.complete = true;
    txn.latency = std::chrono::microseconds(i * 1000);
    txn.request.timestamp = MakeTs(1);
    txn.response.timestamp = MakeTs(1);
    stats.RecordHttpTransaction(txn);
  }

  auto snap = stats.Snapshot();
  EXPECT_EQ(snap.total_requests, 100u);
  EXPECT_NEAR(snap.p50_latency_us, 50000, 5000);
  EXPECT_NEAR(snap.p95_latency_us, 95000, 5000);
  EXPECT_NEAR(snap.p99_latency_us, 99000, 5000);
  EXPECT_EQ(snap.avg_latency_us, 50500);  // avg of 1000..100000
}

TEST(StatisticsTest, RecordPacketThroughput) {
  Statistics stats;

  // 1MB of data in one packet.
  stats.RecordPacket(1'000'000, MakeTs(100));

  auto snap = stats.Snapshot();
  // 1MB = 8Mbits in a 1s window.
  EXPECT_NEAR(snap.throughput_mbps, 8.0, 0.1);
}

TEST(StatisticsTest, StreamTracking) {
  Statistics stats;

  stats.RecordStreamOpen();
  stats.RecordStreamOpen();
  stats.RecordStreamOpen();
  auto snap1 = stats.Snapshot();
  EXPECT_EQ(snap1.active_streams, 3u);

  stats.RecordStreamClose();
  auto snap2 = stats.Snapshot();
  EXPECT_EQ(snap2.active_streams, 2u);
}

TEST(StatisticsTest, IncompleteTransactionIgnored) {
  Statistics stats;

  wirepeek::HttpTransaction txn;
  txn.complete = false;
  stats.RecordHttpTransaction(txn);

  auto snap = stats.Snapshot();
  EXPECT_EQ(snap.total_requests, 0u);
}

TEST(StatisticsTest, Reset) {
  Statistics stats;

  wirepeek::HttpTransaction txn;
  txn.complete = true;
  txn.latency = std::chrono::microseconds(1000);
  txn.request.timestamp = MakeTs(1);
  txn.response.timestamp = MakeTs(1);
  stats.RecordHttpTransaction(txn);
  stats.RecordStreamOpen();

  stats.Reset();
  auto snap = stats.Snapshot();
  EXPECT_EQ(snap.total_requests, 0u);
  EXPECT_EQ(snap.active_streams, 0u);
  EXPECT_EQ(snap.p50_latency_us, 0);
}

}  // namespace
}  // namespace wirepeek::analyzer
