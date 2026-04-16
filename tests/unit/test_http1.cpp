// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/http1.h>

#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace wirepeek::protocol {
namespace {

std::vector<uint8_t> ToBytes(const std::string& s) {
  return {s.begin(), s.end()};
}

wirepeek::Timestamp MakeTs(int seconds) {
  return wirepeek::Timestamp(std::chrono::seconds(seconds));
}

class Http1ParserTest : public ::testing::Test {
 protected:
  std::vector<wirepeek::HttpTransaction> transactions;

  std::unique_ptr<Http1Parser> MakeParser() {
    transactions.clear();
    return std::make_unique<Http1Parser>(
        [this](const wirepeek::HttpTransaction& txn) { transactions.push_back(txn); });
  }
};

TEST_F(Http1ParserTest, SimpleGetRequest) {
  auto parser = MakeParser();
  auto req = ToBytes("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n");
  parser->Feed(req, wirepeek::StreamDirection::kClientToServer, MakeTs(1));

  // Request parsed but no response yet — no transaction emitted.
  EXPECT_TRUE(transactions.empty());
}

TEST_F(Http1ParserTest, SimpleRequestResponse) {
  auto parser = MakeParser();
  auto req = ToBytes("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
  auto resp = ToBytes("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello");

  parser->Feed(req, wirepeek::StreamDirection::kClientToServer, MakeTs(1));
  parser->Feed(resp, wirepeek::StreamDirection::kServerToClient, MakeTs(2));

  ASSERT_EQ(transactions.size(), 1u);
  const auto& txn = transactions[0];
  EXPECT_TRUE(txn.complete);
  EXPECT_EQ(txn.request.method, "GET");
  EXPECT_EQ(txn.request.url, "/");
  EXPECT_EQ(txn.request.version, "HTTP/1.1");
  EXPECT_EQ(txn.response.status_code, 200);
  EXPECT_EQ(txn.response.reason, "OK");
  EXPECT_EQ(txn.response.body_size, 5u);
}

TEST_F(Http1ParserTest, PostRequestWithBody) {
  auto parser = MakeParser();
  auto req = ToBytes(
      "POST /api/users HTTP/1.1\r\n"
      "Host: api.example.com\r\n"
      "Content-Type: application/json\r\n"
      "Content-Length: 25\r\n"
      "\r\n"
      "{\"name\":\"alice\",\"age\":30}");
  auto resp = ToBytes("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n");

  parser->Feed(req, wirepeek::StreamDirection::kClientToServer, MakeTs(1));
  parser->Feed(resp, wirepeek::StreamDirection::kServerToClient, MakeTs(2));

  ASSERT_EQ(transactions.size(), 1u);
  EXPECT_EQ(transactions[0].request.method, "POST");
  EXPECT_EQ(transactions[0].request.url, "/api/users");
  EXPECT_EQ(transactions[0].request.body_size, 25u);
  EXPECT_EQ(transactions[0].response.status_code, 201);
  EXPECT_EQ(transactions[0].response.reason, "Created");
}

TEST_F(Http1ParserTest, MultipleHeaders) {
  auto parser = MakeParser();
  auto req = ToBytes(
      "GET /test HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "Accept: text/html\r\n"
      "User-Agent: wirepeek\r\n"
      "Connection: keep-alive\r\n"
      "\r\n");
  parser->Feed(req, wirepeek::StreamDirection::kClientToServer, MakeTs(1));

  auto resp = ToBytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
  parser->Feed(resp, wirepeek::StreamDirection::kServerToClient, MakeTs(2));

  ASSERT_EQ(transactions.size(), 1u);
  EXPECT_EQ(transactions[0].request.headers.size(), 4u);
  EXPECT_EQ(transactions[0].request.headers[0].first, "Host");
  EXPECT_EQ(transactions[0].request.headers[0].second, "example.com");
  EXPECT_EQ(transactions[0].request.headers[2].first, "User-Agent");
  EXPECT_EQ(transactions[0].request.headers[2].second, "wirepeek");
}

TEST_F(Http1ParserTest, LatencyCalculation) {
  auto parser = MakeParser();
  auto req = ToBytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
  auto resp = ToBytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

  parser->Feed(req, wirepeek::StreamDirection::kClientToServer, MakeTs(10));
  parser->Feed(resp, wirepeek::StreamDirection::kServerToClient, MakeTs(13));

  ASSERT_EQ(transactions.size(), 1u);
  EXPECT_EQ(transactions[0].latency, std::chrono::seconds(3));
}

TEST_F(Http1ParserTest, IncrementalFeeding) {
  auto parser = MakeParser();
  // Feed request in two chunks.
  auto chunk1 = ToBytes("GET / HTTP/1.1\r\nHo");
  auto chunk2 = ToBytes("st: example.com\r\n\r\n");

  parser->Feed(chunk1, wirepeek::StreamDirection::kClientToServer, MakeTs(1));
  EXPECT_TRUE(transactions.empty());

  parser->Feed(chunk2, wirepeek::StreamDirection::kClientToServer, MakeTs(1));
  EXPECT_TRUE(transactions.empty());  // Still waiting for response.

  auto resp = ToBytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
  parser->Feed(resp, wirepeek::StreamDirection::kServerToClient, MakeTs(2));
  ASSERT_EQ(transactions.size(), 1u);
  EXPECT_EQ(transactions[0].request.method, "GET");
}

TEST_F(Http1ParserTest, ResponseWithoutContentLength) {
  auto parser = MakeParser();
  auto req = ToBytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
  auto resp = ToBytes("HTTP/1.1 200 OK\r\n\r\n");

  parser->Feed(req, wirepeek::StreamDirection::kClientToServer, MakeTs(1));
  parser->Feed(resp, wirepeek::StreamDirection::kServerToClient, MakeTs(2));

  ASSERT_EQ(transactions.size(), 1u);
  EXPECT_EQ(transactions[0].response.status_code, 200);
  EXPECT_EQ(transactions[0].response.body_size, 0u);
}

TEST_F(Http1ParserTest, OnCloseEmitsPartialTransaction) {
  auto parser = MakeParser();
  auto req = ToBytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
  parser->Feed(req, wirepeek::StreamDirection::kClientToServer, MakeTs(1));

  EXPECT_TRUE(transactions.empty());

  parser->OnClose();

  ASSERT_EQ(transactions.size(), 1u);
  EXPECT_FALSE(transactions[0].complete);
  EXPECT_EQ(transactions[0].request.method, "GET");
}

TEST_F(Http1ParserTest, Http404Response) {
  auto parser = MakeParser();
  auto req = ToBytes("GET /missing HTTP/1.1\r\nHost: x\r\n\r\n");
  auto resp = ToBytes("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found");

  parser->Feed(req, wirepeek::StreamDirection::kClientToServer, MakeTs(1));
  parser->Feed(resp, wirepeek::StreamDirection::kServerToClient, MakeTs(2));

  ASSERT_EQ(transactions.size(), 1u);
  EXPECT_EQ(transactions[0].response.status_code, 404);
  EXPECT_EQ(transactions[0].response.reason, "Not Found");
  EXPECT_EQ(transactions[0].response.body_size, 9u);
}

}  // namespace
}  // namespace wirepeek::protocol
