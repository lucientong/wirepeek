// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/analyzer/tdigest.h>

#include <cmath>
#include <gtest/gtest.h>

namespace wirepeek::analyzer {
namespace {

TEST(TDigestTest, EmptyReturnsZero) {
  TDigest td;
  EXPECT_DOUBLE_EQ(td.Quantile(0.5), 0.0);
  EXPECT_EQ(td.Count(), 0u);
}

TEST(TDigestTest, SingleValue) {
  TDigest td;
  td.Add(42.0);
  EXPECT_DOUBLE_EQ(td.Quantile(0.5), 42.0);
  EXPECT_EQ(td.Count(), 1u);
}

TEST(TDigestTest, TwoValues) {
  TDigest td;
  td.Add(10.0);
  td.Add(20.0);
  EXPECT_NEAR(td.Quantile(0.0), 10.0, 1.0);
  EXPECT_NEAR(td.Quantile(1.0), 20.0, 1.0);
}

TEST(TDigestTest, UniformDistribution) {
  TDigest td;
  for (int i = 1; i <= 100; ++i) {
    td.Add(static_cast<double>(i));
  }
  EXPECT_EQ(td.Count(), 100u);

  // P50 should be near 50.
  EXPECT_NEAR(td.Quantile(0.50), 50.0, 3.0);
  // P95 should be near 95.
  EXPECT_NEAR(td.Quantile(0.95), 95.0, 3.0);
  // P99 should be near 99.
  EXPECT_NEAR(td.Quantile(0.99), 99.0, 3.0);
}

TEST(TDigestTest, LargeDataset) {
  TDigest td;
  for (int i = 1; i <= 10000; ++i) {
    td.Add(static_cast<double>(i));
  }
  EXPECT_EQ(td.Count(), 10000u);
  EXPECT_NEAR(td.Quantile(0.50), 5000.0, 200.0);
  EXPECT_NEAR(td.Quantile(0.95), 9500.0, 200.0);
  EXPECT_NEAR(td.Quantile(0.99), 9900.0, 200.0);
}

TEST(TDigestTest, Reset) {
  TDigest td;
  td.Add(1.0);
  td.Add(2.0);
  td.Add(3.0);
  EXPECT_EQ(td.Count(), 3u);

  td.Reset();
  EXPECT_EQ(td.Count(), 0u);
  EXPECT_DOUBLE_EQ(td.Quantile(0.5), 0.0);
}

TEST(TDigestTest, AllSameValue) {
  TDigest td;
  for (int i = 0; i < 100; ++i) {
    td.Add(5.0);
  }
  EXPECT_NEAR(td.Quantile(0.5), 5.0, 0.01);
  EXPECT_NEAR(td.Quantile(0.99), 5.0, 0.01);
}

}  // namespace
}  // namespace wirepeek::analyzer
