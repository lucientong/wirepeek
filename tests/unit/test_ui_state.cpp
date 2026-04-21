// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/tui/ui_state.h>

#include <gtest/gtest.h>
#include <string>

namespace wirepeek::tui {
namespace {

TuiEntry MakeEntry(const std::string& proto, const std::string& method, const std::string& url,
                   uint16_t status = 0) {
  TuiEntry e;
  e.protocol = proto;
  e.method = method;
  e.url = url;
  e.status = status;
  return e;
}

TEST(UiStateTest, AddAndGetEntries) {
  UiState state;
  state.AddEntry(MakeEntry("HTTP", "GET", "/api"));
  state.AddEntry(MakeEntry("TCP", "", "client->server"));

  auto entries = state.GetEntries();
  EXPECT_EQ(entries.size(), 2u);
  EXPECT_EQ(entries[0].protocol, "HTTP");
  EXPECT_EQ(entries[1].protocol, "TCP");
}

TEST(UiStateTest, MaxEntriesEviction) {
  UiState state;
  for (size_t i = 0; i < UiState::kMaxEntries + 100; ++i) {
    state.AddEntry(MakeEntry("TCP", "", std::to_string(i)));
  }
  EXPECT_EQ(state.EntryCount(), UiState::kMaxEntries);
  // Oldest should be evicted — first entry should be "100" not "0".
  auto entries = state.GetEntries();
  EXPECT_EQ(entries.front().url, "100");
}

TEST(UiStateTest, FilterByProtocol) {
  UiState state;
  state.AddEntry(MakeEntry("HTTP", "GET", "/api"));
  state.AddEntry(MakeEntry("TCP", "", "raw data"));
  state.AddEntry(MakeEntry("HTTP", "POST", "/login"));
  state.AddEntry(MakeEntry("UDP", "", "dns query"));

  auto http = state.GetFilteredEntries("http");
  EXPECT_EQ(http.size(), 2u);

  auto tcp = state.GetFilteredEntries("tcp");
  EXPECT_EQ(tcp.size(), 1u);

  auto udp = state.GetFilteredEntries("UDP");
  EXPECT_EQ(udp.size(), 1u);
}

TEST(UiStateTest, FilterByUrl) {
  UiState state;
  state.AddEntry(MakeEntry("HTTP", "GET", "/api/users"));
  state.AddEntry(MakeEntry("HTTP", "GET", "/api/posts"));
  state.AddEntry(MakeEntry("HTTP", "GET", "/health"));

  auto api = state.GetFilteredEntries("api");
  EXPECT_EQ(api.size(), 2u);

  auto health = state.GetFilteredEntries("health");
  EXPECT_EQ(health.size(), 1u);
}

TEST(UiStateTest, FilterByMethod) {
  UiState state;
  state.AddEntry(MakeEntry("HTTP", "GET", "/a"));
  state.AddEntry(MakeEntry("HTTP", "POST", "/b"));
  state.AddEntry(MakeEntry("HTTP", "GET", "/c"));

  auto post = state.GetFilteredEntries("post");
  EXPECT_EQ(post.size(), 1u);
  EXPECT_EQ(post[0].url, "/b");
}

TEST(UiStateTest, FilterCaseInsensitive) {
  UiState state;
  state.AddEntry(MakeEntry("HTTP", "GET", "/API/Users"));

  auto lower = state.GetFilteredEntries("api/users");
  EXPECT_EQ(lower.size(), 1u);

  auto upper = state.GetFilteredEntries("API/USERS");
  EXPECT_EQ(upper.size(), 1u);
}

TEST(UiStateTest, EmptyFilterReturnsAll) {
  UiState state;
  state.AddEntry(MakeEntry("HTTP", "GET", "/a"));
  state.AddEntry(MakeEntry("TCP", "", "/b"));

  auto all = state.GetFilteredEntries("");
  EXPECT_EQ(all.size(), 2u);
}

TEST(UiStateTest, StatsTracking) {
  UiState state;
  state.IncrementPackets(100);
  state.IncrementPackets(200);
  state.SetStreamCount(5);
  state.IncrementHttpTransactions();

  auto stats = state.GetStats();
  EXPECT_EQ(stats.packet_count, 2u);
  EXPECT_EQ(stats.total_bytes, 300u);
  EXPECT_EQ(stats.stream_count, 5u);
  EXPECT_EQ(stats.http_txn_count, 1u);
}

TEST(UiStateTest, SparklinePps) {
  UiState state;
  state.PushPpsSample(100);
  state.PushPpsSample(200);
  state.PushPpsSample(150);

  auto stats = state.GetStats();
  EXPECT_EQ(stats.pps_history.size(), 3u);
  EXPECT_EQ(stats.pps_history[0], 100);
  EXPECT_EQ(stats.pps_history[1], 200);
  EXPECT_EQ(stats.pps_history[2], 150);
}

TEST(UiStateTest, SparklineMaxLength) {
  UiState state;
  for (int i = 0; i < 100; ++i) {
    state.PushPpsSample(i);
  }
  auto stats = state.GetStats();
  // Should be capped at 60 entries.
  EXPECT_EQ(stats.pps_history.size(), 60u);
  // First entry should be 40 (oldest 40 evicted).
  EXPECT_EQ(stats.pps_history.front(), 40);
}

}  // namespace
}  // namespace wirepeek::tui
