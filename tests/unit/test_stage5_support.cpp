// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/analyzer/metrics_server.h>
#include <wirepeek/protocol/tls_keylog.h>

#include <gtest/gtest.h>

TEST(MetricsServerTest, RendersBoundedLabelsAndCounters) {
  auto statistics = std::make_shared<wirepeek::analyzer::Statistics>();
  auto endpoints = std::make_shared<wirepeek::analyzer::EndpointStats>();
  wirepeek::HttpTransaction transaction;
  transaction.complete = true;
  transaction.request.method = "GET";
  transaction.request.url = "/users/42?token=secret";
  transaction.response.status_code = 404;
  transaction.latency = std::chrono::microseconds(2000);
  endpoints->Record(transaction);
  statistics->RecordHttpTransaction(transaction);
  statistics->RecordPacket(64, {});

  wirepeek::analyzer::MetricsServer server(statistics, endpoints);
  const auto metrics = server.Render();
  EXPECT_NE(metrics.find("route=\"/users/:id\""), std::string::npos);
  EXPECT_NE(metrics.find("status_class=\"4xx\""), std::string::npos);
  EXPECT_NE(metrics.find("wirepeek_packets_total 1"), std::string::npos);
  EXPECT_EQ(metrics.find("token=secret"), std::string::npos);
}

TEST(TlsKeyLogTest, ParsesAndFindsSecret) {
  wirepeek::protocol::TlsKeyLog keylog;
  const std::string random(64, 'a');
  EXPECT_TRUE(keylog.ParseLine("CLIENT_RANDOM " + random + " 001122ff"));
  ASSERT_NE(keylog.Find("CLIENT_RANDOM", random), nullptr);
  EXPECT_EQ(keylog.Find("CLIENT_RANDOM", random)->size(), 4);
  EXPECT_FALSE(keylog.ParseLine("invalid"));
}
