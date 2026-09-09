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

  EXPECT_TRUE(transactions.empty());
  parser->OnClose();
  ASSERT_EQ(transactions.size(), 1u);
  EXPECT_TRUE(transactions[0].complete);
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

TEST_F(Http1ParserTest, ParsesPipelinedMessagesInSingleFeeds) {
  auto parser = MakeParser();
  auto requests = ToBytes("GET /one HTTP/1.1\r\nHost: x\r\n\r\n"
                          "GET /two HTTP/1.1\r\nHost: x\r\n\r\n");
  auto responses = ToBytes("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA"
                           "HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nBC");

  parser->Feed(requests, wirepeek::StreamDirection::kClientToServer, MakeTs(1));
  parser->Feed(responses, wirepeek::StreamDirection::kServerToClient, MakeTs(2));

  ASSERT_EQ(transactions.size(), 2u);
  EXPECT_EQ(transactions[0].request.url, "/one");
  EXPECT_EQ(transactions[0].response.body_size, 1u);
  EXPECT_EQ(transactions[1].request.url, "/two");
  EXPECT_EQ(transactions[1].response.status_code, 201);
  EXPECT_EQ(transactions[1].response.body_size, 2u);
}

TEST_F(Http1ParserTest, ParsesChunkedRequestAndResponseIncrementally) {
  auto parser = MakeParser();
  auto request1 = ToBytes("POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWi");
  auto request2 = ToBytes("ki\r\n5;ext=yes\r\npedia\r\n0\r\nX-Trailer: yes\r\n\r\n");
  auto response1 =
      ToBytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n");
  auto response2 = ToBytes("2\r\nde\r\n0\r\n\r\n");

  parser->Feed(request1, wirepeek::StreamDirection::kClientToServer, MakeTs(1));
  parser->Feed(request2, wirepeek::StreamDirection::kClientToServer, MakeTs(2));
  parser->Feed(response1, wirepeek::StreamDirection::kServerToClient, MakeTs(3));
  parser->Feed(response2, wirepeek::StreamDirection::kServerToClient, MakeTs(4));

  ASSERT_EQ(transactions.size(), 1u);
  EXPECT_EQ(transactions[0].request.body_size, 9u);
  EXPECT_EQ(transactions[0].response.body_size, 5u);
}

TEST_F(Http1ParserTest, HeadAndBodylessStatusesIgnoreContentLength) {
  auto parser = MakeParser();
  auto requests = ToBytes("HEAD /head HTTP/1.1\r\nHost: x\r\n\r\n"
                          "GET /empty HTTP/1.1\r\nHost: x\r\n\r\n"
                          "GET /cached HTTP/1.1\r\nHost: x\r\n\r\n");
  auto responses = ToBytes("HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n"
                           "HTTP/1.1 204 No Content\r\nContent-Length: 88\r\n\r\n"
                           "HTTP/1.1 304 Not Modified\r\nContent-Length: 77\r\n\r\n");

  parser->Feed(requests, wirepeek::StreamDirection::kClientToServer, MakeTs(1));
  parser->Feed(responses, wirepeek::StreamDirection::kServerToClient, MakeTs(2));

  ASSERT_EQ(transactions.size(), 3u);
  EXPECT_EQ(transactions[0].response.body_size, 0u);
  EXPECT_EQ(transactions[1].response.status_code, 204);
  EXPECT_EQ(transactions[2].response.status_code, 304);
}

TEST_F(Http1ParserTest, InformationalResponseDoesNotConsumeRequest) {
  auto parser = MakeParser();
  auto req = ToBytes("POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
  auto resp = ToBytes("HTTP/1.1 100 Continue\r\n\r\n"
                      "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

  parser->Feed(req, wirepeek::StreamDirection::kClientToServer, MakeTs(1));
  parser->Feed(resp, wirepeek::StreamDirection::kServerToClient, MakeTs(2));

  ASSERT_EQ(transactions.size(), 1u);
  EXPECT_EQ(transactions[0].response.status_code, 200);
}

TEST_F(Http1ParserTest, UntilCloseBodyCompletesOnClose) {
  auto parser = MakeParser();
  auto req = ToBytes("GET /download HTTP/1.1\r\nHost: x\r\n\r\n");
  auto resp1 = ToBytes("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello ");
  auto resp2 = ToBytes("world");

  parser->Feed(req, wirepeek::StreamDirection::kClientToServer, MakeTs(1));
  parser->Feed(resp1, wirepeek::StreamDirection::kServerToClient, MakeTs(2));
  parser->Feed(resp2, wirepeek::StreamDirection::kServerToClient, MakeTs(3));
  EXPECT_TRUE(transactions.empty());

  parser->OnClose();
  ASSERT_EQ(transactions.size(), 1u);
  EXPECT_TRUE(transactions[0].complete);
  EXPECT_EQ(transactions[0].response.body_size, 11u);
}

TEST_F(Http1ParserTest, SwitchingProtocolsEmitsThenSignalsUpgrade) {
  bool upgraded = false;
  auto parser = std::make_unique<Http1Parser>(
      [this](const wirepeek::HttpTransaction& txn) { transactions.push_back(txn); },
      [&] { upgraded = true; });
  auto req = ToBytes("GET /chat HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
  auto resp = ToBytes(
      "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n");

  parser->Feed(req, wirepeek::StreamDirection::kClientToServer, MakeTs(1));
  parser->Feed(resp, wirepeek::StreamDirection::kServerToClient, MakeTs(2));

  ASSERT_EQ(transactions.size(), 1u);
  EXPECT_EQ(transactions[0].response.status_code, 101);
  EXPECT_TRUE(upgraded);
  EXPECT_TRUE(parser->IsUpgraded());
}

TEST_F(Http1ParserTest, OnCloseEmitsEveryPendingPipelinedRequest) {
  auto parser = MakeParser();
  auto requests = ToBytes("GET /one HTTP/1.1\r\nHost: x\r\n\r\n"
                          "GET /two HTTP/1.1\r\nHost: x\r\n\r\n");
  parser->Feed(requests, wirepeek::StreamDirection::kClientToServer, MakeTs(1));

  parser->OnClose();

  ASSERT_EQ(transactions.size(), 2u);
  EXPECT_FALSE(transactions[0].complete);
  EXPECT_FALSE(transactions[1].complete);
  EXPECT_EQ(transactions[1].request.url, "/two");
}

}  // namespace
}  // namespace wirepeek::protocol
