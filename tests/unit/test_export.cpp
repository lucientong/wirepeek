// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/export/har_writer.h>
#include <wirepeek/export/json_writer.h>
#include <wirepeek/export/pcap_writer.h>

#include <chrono>
#include <cstdio>
#include <fmt/format.h>
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <vector>

namespace wirepeek::exporter {
namespace {

wirepeek::Timestamp MakeTs(int seconds) {
  return wirepeek::Timestamp(std::chrono::seconds(seconds));
}

// ── PcapWriter ────────────────────────────────────────────────────────────────

TEST(PcapWriterTest, WriteSinglePacket) {
  std::string path = "/tmp/wirepeek_test.pcap";
  {
    PcapWriter writer(path);
    std::vector<uint8_t> data = {0xAA, 0xBB, 0xCC, 0xDD};
    PacketView pkt{
        .data = data, .timestamp = MakeTs(1000), .capture_length = 4, .original_length = 4};
    writer.WritePacket(pkt);
    EXPECT_EQ(writer.PacketCount(), 1u);
  }

  // Verify file exists and has content: 24 (file header) + 16 (packet header) + 4 (data) = 44.
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  ASSERT_TRUE(file.is_open());
  EXPECT_EQ(file.tellg(), 44);
  std::remove(path.c_str());
}

TEST(PcapWriterTest, WriteMultiplePackets) {
  std::string path = "/tmp/wirepeek_test2.pcap";
  {
    PcapWriter writer(path);
    std::vector<uint8_t> data = {0x01, 0x02};
    PacketView pkt{.data = data, .timestamp = MakeTs(1), .capture_length = 2, .original_length = 2};
    writer.WritePacket(pkt);
    writer.WritePacket(pkt);
    writer.WritePacket(pkt);
    EXPECT_EQ(writer.PacketCount(), 3u);
  }
  // 24 + 3 * (16 + 2) = 78 bytes.
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  EXPECT_EQ(file.tellg(), 78);
  std::remove(path.c_str());
}

// ── HarWriter ─────────────────────────────────────────────────────────────────

TEST(HarWriterTest, EmptyHar) {
  HarWriter writer;
  auto json = writer.ToJson();
  EXPECT_NE(json.find("\"version\": \"1.2\""), std::string::npos);
  EXPECT_NE(json.find("\"entries\":"), std::string::npos);
}

TEST(HarWriterTest, SingleTransaction) {
  HarWriter writer;
  HttpTransaction txn;
  txn.request.method = "GET";
  txn.request.url = "/api/users";
  txn.request.version = "HTTP/1.1";
  txn.request.timestamp = MakeTs(1000);
  txn.response.status_code = 200;
  txn.response.reason = "OK";
  txn.response.version = "HTTP/1.1";
  txn.response.body_size = 42;
  txn.response.timestamp = MakeTs(1001);
  txn.latency = std::chrono::milliseconds(50);
  txn.complete = true;

  writer.AddTransaction(txn);
  EXPECT_EQ(writer.TransactionCount(), 1u);

  auto json = writer.ToJson();
  EXPECT_NE(json.find("\"method\": \"GET\""), std::string::npos);
  EXPECT_NE(json.find("\"url\": \"/api/users\""), std::string::npos);
  EXPECT_NE(json.find("\"status\": 200"), std::string::npos);
  EXPECT_NE(json.find("\"bodySize\": 42"), std::string::npos);
}

TEST(HarWriterTest, WriteToFile) {
  std::string path = "/tmp/wirepeek_test.har";
  HarWriter writer;
  HttpTransaction txn;
  txn.request.method = "POST";
  txn.request.url = "/submit";
  txn.request.version = "HTTP/1.1";
  txn.request.timestamp = MakeTs(500);
  txn.complete = true;
  writer.AddTransaction(txn);
  writer.WriteToFile(path);

  std::ifstream file(path);
  ASSERT_TRUE(file.is_open());
  std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  EXPECT_NE(content.find("\"method\": \"POST\""), std::string::npos);
  std::remove(path.c_str());
}

// ── JsonWriter ────────────────────────────────────────────────────────────────

TEST(JsonWriterTest, WritePacket) {
  std::string path = "/tmp/wirepeek_test.jsonl";
  {
    JsonWriter writer(path);
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    PacketView pkt{.data = data, .timestamp = MakeTs(100), .capture_length = 3};
    dissector::DissectedPacket dissected;
    writer.WritePacket(pkt, dissected);
    EXPECT_EQ(writer.LineCount(), 1u);
  }

  std::ifstream file(path);
  std::string line;
  std::getline(file, line);
  EXPECT_NE(line.find("\"type\":\"packet\""), std::string::npos);
  EXPECT_NE(line.find("\"len\":3"), std::string::npos);
  std::remove(path.c_str());
}

TEST(JsonWriterTest, WriteHttpTransaction) {
  std::string path = "/tmp/wirepeek_test_http.jsonl";
  {
    JsonWriter writer(path);
    HttpTransaction txn;
    txn.request.method = "GET";
    txn.request.url = "/test";
    txn.request.timestamp = MakeTs(200);
    txn.response.status_code = 200;
    txn.latency = std::chrono::microseconds(5000);
    txn.complete = true;
    writer.WriteHttpTransaction(txn);
  }

  std::ifstream file(path);
  std::string line;
  std::getline(file, line);
  EXPECT_NE(line.find("\"type\":\"http\""), std::string::npos);
  EXPECT_NE(line.find("\"method\":\"GET\""), std::string::npos);
  EXPECT_NE(line.find("\"latency_us\":5000"), std::string::npos);
  std::remove(path.c_str());
}

// ── Additional PcapWriter Edge Cases ────────────────────────────────────────

TEST(PcapWriterTest, FileCreationFailure) {
  std::string invalid_path = "/nonexistent/directory/file.pcap";
  EXPECT_THROW(PcapWriter writer(invalid_path), std::runtime_error);
}

TEST(PcapWriterTest, JumboPayload) {
  std::string path = "/tmp/wirepeek_jumbo.pcap";
  {
    PcapWriter writer(path);
    std::vector<uint8_t> data(10000, 0xAA);
    PacketView pkt{
        .data = data, .timestamp = MakeTs(1000), .capture_length = 10000, .original_length = 10000};
    writer.WritePacket(pkt);
    EXPECT_EQ(writer.PacketCount(), 1u);
  }
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  ASSERT_TRUE(file.is_open());
  EXPECT_EQ(file.tellg(), 10040);
  std::remove(path.c_str());
}

TEST(PcapWriterTest, ZeroLengthPayload) {
  std::string path = "/tmp/wirepeek_empty_payload.pcap";
  {
    PcapWriter writer(path);
    std::vector<uint8_t> data;
    PacketView pkt{
        .data = data, .timestamp = MakeTs(1000), .capture_length = 0, .original_length = 0};
    writer.WritePacket(pkt);
    EXPECT_EQ(writer.PacketCount(), 1u);
  }
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  ASSERT_TRUE(file.is_open());
  EXPECT_EQ(file.tellg(), 40);
  std::remove(path.c_str());
}

TEST(HarWriterTest, SpecialCharactersInUrl) {
  HarWriter writer;
  HttpTransaction txn;
  txn.request.method = "GET";
  txn.request.url = "/search?q=hello&world=1";
  txn.request.version = "HTTP/1.1";
  txn.request.timestamp = MakeTs(100);
  txn.response.status_code = 200;
  txn.response.reason = "OK";
  txn.response.version = "HTTP/1.1";
  txn.complete = true;

  writer.AddTransaction(txn);
  auto json = writer.ToJson();
  EXPECT_NE(json.find("&world"), std::string::npos);
}

TEST(HarWriterTest, MultipleTransactions) {
  HarWriter writer;
  for (int i = 0; i < 5; ++i) {
    HttpTransaction txn;
    txn.request.method = "GET";
    txn.request.url = fmt::format("/page{}", i);
    txn.request.version = "HTTP/1.1";
    txn.request.timestamp = MakeTs(100 + i);
    txn.response.status_code = 200;
    txn.response.reason = "OK";
    txn.response.version = "HTTP/1.1";
    txn.complete = true;
    writer.AddTransaction(txn);
  }
  EXPECT_EQ(writer.TransactionCount(), 5u);
  auto json = writer.ToJson();
  EXPECT_NE(json.find("/page0"), std::string::npos);
  EXPECT_NE(json.find("/page4"), std::string::npos);
}

TEST(HarWriterTest, LargeResponseBody) {
  HarWriter writer;
  HttpTransaction txn;
  txn.request.method = "GET";
  txn.request.url = "/large";
  txn.request.version = "HTTP/1.1";
  txn.request.timestamp = MakeTs(100);
  txn.response.status_code = 200;
  txn.response.reason = "OK";
  txn.response.version = "HTTP/1.1";
  txn.response.body_size = 1000000;
  txn.complete = true;

  writer.AddTransaction(txn);
  auto json = writer.ToJson();
  EXPECT_NE(json.find("1000000"), std::string::npos);
}

TEST(JsonWriterTest, WriteToStdout) {
  JsonWriter writer("-");
  EXPECT_EQ(writer.LineCount(), 0u);
  std::vector<uint8_t> data = {0x01, 0x02, 0x03};
  PacketView pkt{.data = data, .timestamp = MakeTs(100), .capture_length = 3};
  dissector::DissectedPacket dissected;
  writer.WritePacket(pkt, dissected);
  EXPECT_EQ(writer.LineCount(), 1u);
}

TEST(JsonWriterTest, HttpFieldsComplete) {
  std::string path = "/tmp/wirepeek_http_fields.jsonl";
  {
    JsonWriter writer(path);
    HttpTransaction txn;
    txn.request.method = "PUT";
    txn.request.url = "/update";
    txn.request.timestamp = MakeTs(500);
    txn.request.body_size = 256;
    txn.response.status_code = 202;
    txn.response.body_size = 512;
    txn.latency = std::chrono::microseconds(50000);
    txn.complete = true;
    writer.WriteHttpTransaction(txn);
  }

  std::ifstream file(path);
  std::string line;
  std::getline(file, line);
  EXPECT_NE(line.find("\"type\":\"http\""), std::string::npos);
  EXPECT_NE(line.find("\"method\":\"PUT\""), std::string::npos);
  EXPECT_NE(line.find("\"latency_us\":50000"), std::string::npos);
  std::remove(path.c_str());
}

TEST(JsonWriterTest, IncompleteTransaction) {
  std::string path = "/tmp/wirepeek_incomplete.jsonl";
  {
    JsonWriter writer(path);
    HttpTransaction txn;
    txn.request.method = "GET";
    txn.request.url = "/timeout";
    txn.request.timestamp = MakeTs(100);
    txn.complete = false;
    writer.WriteHttpTransaction(txn);
  }

  std::ifstream file(path);
  std::string line;
  std::getline(file, line);
  EXPECT_NE(line.find("\"complete\":false"), std::string::npos);
  std::remove(path.c_str());
}

}  // namespace
}  // namespace wirepeek::exporter
