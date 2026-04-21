// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/protocol_handler.h>

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace wirepeek::protocol {
namespace {

wirepeek::Timestamp MakeTs(int seconds) {
  return wirepeek::Timestamp(std::chrono::seconds(seconds));
}

std::vector<uint8_t> ToBytes(const std::string& s) {
  return {s.begin(), s.end()};
}

// Helper to create IPv4 address from octets
wirepeek::dissector::Ipv4Address MakeIpv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
  return wirepeek::dissector::Ipv4Address{a, b, c, d};
}

// Helper to create a ConnectionKey from IPs and ports
wirepeek::ConnectionKey MakeConnectionKey(const wirepeek::dissector::Ipv4Address& src_ip,
                                          uint16_t src_port,
                                          const wirepeek::dissector::Ipv4Address& dst_ip,
                                          uint16_t dst_port) {
  wirepeek::ConnectionKey key;
  // Convert Ipv4Address to the first 4 bytes of the array
  for (size_t i = 0; i < 4; ++i) {
    key.src_ip[i] = src_ip[i];
    key.dst_ip[i] = dst_ip[i];
  }
  key.src_port = src_port;
  key.dst_port = dst_port;
  key.ip_version = 4;
  key.protocol = 6;  // TCP
  return key;
}

wirepeek::dissector::StreamEvent MakeStreamEvent(
    const wirepeek::ConnectionKey& key, wirepeek::dissector::StreamEventType type,
    const std::vector<uint8_t>& data = {},
    wirepeek::StreamDirection dir = wirepeek::StreamDirection::kClientToServer) {
  return wirepeek::dissector::StreamEvent{
      .key = key,
      .type = type,
      .data = data,
      .direction = dir,
  };
}

// ── StreamLifecycle ────────────────────────────────────────────────────────────

TEST(ProtocolHandlerTest, StreamOpenAndClose) {
  std::vector<wirepeek::HttpTransaction> http_txns;
  wirepeek::protocol::ProtocolHandler handler(
      [&](const wirepeek::ConnectionKey& /*key*/, const wirepeek::HttpTransaction& txn) {
        http_txns.push_back(txn);
      });

  auto key = MakeConnectionKey(MakeIpv4(192, 168, 1, 1), 12345, MakeIpv4(192, 168, 1, 2), 80);
  auto open_event = MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kOpen);

  // Should not crash.
  handler.OnStreamEvent(open_event, MakeTs(1));
  EXPECT_TRUE(http_txns.empty());

  // Close without data should not crash.
  auto close_event = MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kClose);
  handler.OnStreamEvent(close_event, MakeTs(2));
  EXPECT_TRUE(http_txns.empty());
}

// ── Protocol Detection and HTTP Routing ────────────────────────────────────────

TEST(ProtocolHandlerTest, DetectHttpAndRoute) {
  std::vector<wirepeek::HttpTransaction> http_txns;
  wirepeek::protocol::ProtocolHandler handler(
      [&](const wirepeek::ConnectionKey& /*key*/, const wirepeek::HttpTransaction& txn) {
        http_txns.push_back(txn);
      });

  auto key = MakeConnectionKey(MakeIpv4(192, 168, 1, 1), 12345, MakeIpv4(192, 168, 1, 2), 80);

  // Open stream.
  auto open_event = MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kOpen);
  handler.OnStreamEvent(open_event, MakeTs(1));

  // Send HTTP request (should trigger protocol detection).
  auto req = ToBytes("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
  auto req_event = MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kData, req,
                                   wirepeek::StreamDirection::kClientToServer);
  handler.OnStreamEvent(req_event, MakeTs(2));

  // Send HTTP response.
  auto resp = ToBytes("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello");
  auto resp_event = MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kData, resp,
                                    wirepeek::StreamDirection::kServerToClient);
  handler.OnStreamEvent(resp_event, MakeTs(3));

  // Should have parsed HTTP transaction.
  ASSERT_EQ(http_txns.size(), 1u);
  EXPECT_EQ(http_txns[0].request.method, "GET");
  EXPECT_EQ(http_txns[0].request.url, "/");
  EXPECT_EQ(http_txns[0].response.status_code, 200);
}

// ── Unknown Protocol Fallback ────────────────────────────────────────────────────

TEST(ProtocolHandlerTest, UnknownProtocolWithRawDataCallback) {
  std::vector<wirepeek::HttpTransaction> http_txns;
  std::vector<std::pair<wirepeek::StreamDirection, size_t>> raw_data_calls;

  wirepeek::protocol::ProtocolHandler handler(
      [&](const wirepeek::ConnectionKey& /*key*/, const wirepeek::HttpTransaction& txn) {
        http_txns.push_back(txn);
      },
      [&](const wirepeek::ConnectionKey& /*key*/, wirepeek::StreamDirection dir,
          std::span<const uint8_t> data) { raw_data_calls.push_back({dir, data.size()}); });

  auto key = MakeConnectionKey(MakeIpv4(192, 168, 1, 1), 12345, MakeIpv4(192, 168, 1, 2), 80);

  // Open stream.
  auto open_event = MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kOpen);
  handler.OnStreamEvent(open_event, MakeTs(1));

  // Send unknown data (not HTTP).
  auto unknown_data = ToBytes("UNKNOWN_PROTOCOL_DATA");
  auto data_event = MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kData, unknown_data,
                                    wirepeek::StreamDirection::kClientToServer);
  handler.OnStreamEvent(data_event, MakeTs(2));

  // Should have called raw data callback, not HTTP callback.
  EXPECT_TRUE(http_txns.empty());
  ASSERT_EQ(raw_data_calls.size(), 1u);
  EXPECT_EQ(raw_data_calls[0].first, wirepeek::StreamDirection::kClientToServer);
  EXPECT_EQ(raw_data_calls[0].second, unknown_data.size());
}

// ── Multiple Concurrent Streams ────────────────────────────────────────────────

TEST(ProtocolHandlerTest, MultipleConcurrentStreams) {
  std::vector<wirepeek::HttpTransaction> http_txns;
  wirepeek::protocol::ProtocolHandler handler(
      [&](const wirepeek::ConnectionKey& /*key*/, const wirepeek::HttpTransaction& txn) {
        http_txns.push_back(txn);
      });

  // Stream 1: GET /page1
  auto key1 = MakeConnectionKey(MakeIpv4(192, 168, 1, 1), 1001, MakeIpv4(192, 168, 1, 2), 80);
  auto open1 = MakeStreamEvent(key1, wirepeek::dissector::StreamEventType::kOpen);
  handler.OnStreamEvent(open1, MakeTs(1));

  auto req1 = ToBytes("GET /page1 HTTP/1.1\r\nHost: example.com\r\n\r\n");
  auto data1 = MakeStreamEvent(key1, wirepeek::dissector::StreamEventType::kData, req1,
                               wirepeek::StreamDirection::kClientToServer);
  handler.OnStreamEvent(data1, MakeTs(2));

  // Stream 2: POST /api
  auto key2 = MakeConnectionKey(MakeIpv4(192, 168, 1, 1), 1002, MakeIpv4(192, 168, 1, 2), 80);
  auto open2 = MakeStreamEvent(key2, wirepeek::dissector::StreamEventType::kOpen);
  handler.OnStreamEvent(open2, MakeTs(3));

  auto req2 = ToBytes("POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n");
  auto data2 = MakeStreamEvent(key2, wirepeek::dissector::StreamEventType::kData, req2,
                               wirepeek::StreamDirection::kClientToServer);
  handler.OnStreamEvent(data2, MakeTs(4));

  // Send responses.
  auto resp1 = ToBytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
  auto resp_data1 = MakeStreamEvent(key1, wirepeek::dissector::StreamEventType::kData, resp1,
                                    wirepeek::StreamDirection::kServerToClient);
  handler.OnStreamEvent(resp_data1, MakeTs(5));

  auto resp2 = ToBytes("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n");
  auto resp_data2 = MakeStreamEvent(key2, wirepeek::dissector::StreamEventType::kData, resp2,
                                    wirepeek::StreamDirection::kServerToClient);
  handler.OnStreamEvent(resp_data2, MakeTs(6));

  // Should have parsed both transactions.
  ASSERT_EQ(http_txns.size(), 2u);
  EXPECT_EQ(http_txns[0].request.url, "/page1");
  EXPECT_EQ(http_txns[0].response.status_code, 200);
  EXPECT_EQ(http_txns[1].request.url, "/api");
  EXPECT_EQ(http_txns[1].response.status_code, 201);
}

// ── Stream Closure and Cleanup ────────────────────────────────────────────────

TEST(ProtocolHandlerTest, StreamCloseTriggersCleanup) {
  std::vector<wirepeek::HttpTransaction> http_txns;
  wirepeek::protocol::ProtocolHandler handler(
      [&](const wirepeek::ConnectionKey& /*key*/, const wirepeek::HttpTransaction& txn) {
        http_txns.push_back(txn);
      });

  auto key = MakeConnectionKey(MakeIpv4(192, 168, 1, 1), 12345, MakeIpv4(192, 168, 1, 2), 80);

  // Open and send data.
  auto open_event = MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kOpen);
  handler.OnStreamEvent(open_event, MakeTs(1));

  auto req = ToBytes("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
  auto data_event = MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kData, req,
                                    wirepeek::StreamDirection::kClientToServer);
  handler.OnStreamEvent(data_event, MakeTs(2));

  // Close stream.
  auto close_event = MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kClose);
  handler.OnStreamEvent(close_event, MakeTs(3));

  // Should not crash when re-opening same key.
  auto open_again = MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kOpen);
  handler.OnStreamEvent(open_again, MakeTs(4));

  auto req2 = ToBytes("POST / HTTP/1.1\r\nHost: example.com\r\n\r\n");
  auto data_event2 = MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kData, req2,
                                     wirepeek::StreamDirection::kClientToServer);
  handler.OnStreamEvent(data_event2, MakeTs(5));

  // Verify no crash and reasonable state.
  EXPECT_TRUE(http_txns.empty() || http_txns.size() <= 2);
}

// ── Interleaved Stream Data ────────────────────────────────────────────────────

TEST(ProtocolHandlerTest, InterleavedStreamData) {
  std::vector<wirepeek::HttpTransaction> http_txns;
  wirepeek::protocol::ProtocolHandler handler(
      [&](const wirepeek::ConnectionKey& /*key*/, const wirepeek::HttpTransaction& txn) {
        http_txns.push_back(txn);
      });

  // Two streams.
  auto key1 = MakeConnectionKey(MakeIpv4(192, 168, 1, 1), 1001, MakeIpv4(192, 168, 1, 2), 80);
  auto key2 = MakeConnectionKey(MakeIpv4(192, 168, 1, 1), 1002, MakeIpv4(192, 168, 1, 2), 80);

  // Interleave: open 1, open 2, data 1, data 2, response 1, response 2.
  handler.OnStreamEvent(MakeStreamEvent(key1, wirepeek::dissector::StreamEventType::kOpen),
                        MakeTs(1));
  handler.OnStreamEvent(MakeStreamEvent(key2, wirepeek::dissector::StreamEventType::kOpen),
                        MakeTs(2));

  auto req1 = ToBytes("GET /1 HTTP/1.1\r\nHost: a.com\r\n\r\n");
  handler.OnStreamEvent(MakeStreamEvent(key1, wirepeek::dissector::StreamEventType::kData, req1,
                                        wirepeek::StreamDirection::kClientToServer),
                        MakeTs(3));

  auto req2 = ToBytes("GET /2 HTTP/1.1\r\nHost: b.com\r\n\r\n");
  handler.OnStreamEvent(MakeStreamEvent(key2, wirepeek::dissector::StreamEventType::kData, req2,
                                        wirepeek::StreamDirection::kClientToServer),
                        MakeTs(4));

  auto resp1 = ToBytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
  handler.OnStreamEvent(MakeStreamEvent(key1, wirepeek::dissector::StreamEventType::kData, resp1,
                                        wirepeek::StreamDirection::kServerToClient),
                        MakeTs(5));

  auto resp2 = ToBytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
  handler.OnStreamEvent(MakeStreamEvent(key2, wirepeek::dissector::StreamEventType::kData, resp2,
                                        wirepeek::StreamDirection::kServerToClient),
                        MakeTs(6));

  // Should track both independently.
  ASSERT_EQ(http_txns.size(), 2u);
  EXPECT_EQ(http_txns[0].request.url, "/1");
  EXPECT_EQ(http_txns[1].request.url, "/2");
}

// ── HTTP Parser Callback Invocation ────────────────────────────────────────────

TEST(ProtocolHandlerTest, HttpCallbackInvoked) {
  int callback_count = 0;
  wirepeek::ConnectionKey last_key;
  wirepeek::HttpTransaction last_txn;

  wirepeek::protocol::ProtocolHandler handler(
      [&](const wirepeek::ConnectionKey& key, const wirepeek::HttpTransaction& txn) {
        ++callback_count;
        last_key = key;
        last_txn = txn;
      });

  auto key = MakeConnectionKey(MakeIpv4(192, 168, 1, 1), 5000, MakeIpv4(192, 168, 1, 2), 443);

  handler.OnStreamEvent(MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kOpen),
                        MakeTs(1));

  auto req = ToBytes("GET /secure HTTP/1.1\r\nHost: secure.example.com\r\n\r\n");
  handler.OnStreamEvent(MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kData, req,
                                        wirepeek::StreamDirection::kClientToServer),
                        MakeTs(2));

  auto resp = ToBytes("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nSecure data");
  handler.OnStreamEvent(MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kData, resp,
                                        wirepeek::StreamDirection::kServerToClient),
                        MakeTs(3));

  // Callback should have been invoked exactly once.
  EXPECT_EQ(callback_count, 1);
  EXPECT_EQ(last_key.src_port, 5000);
  EXPECT_EQ(last_key.dst_port, 443);
  EXPECT_EQ(last_txn.request.url, "/secure");
  EXPECT_EQ(last_txn.response.body_size, 11u);
}

// ── Null Raw Callback Handling ────────────────────────────────────────────────

TEST(ProtocolHandlerTest, NullRawCallbackSafe) {
  std::vector<wirepeek::HttpTransaction> http_txns;

  // Explicitly pass nullptr for raw_cb.
  wirepeek::protocol::ProtocolHandler handler(
      [&](const wirepeek::ConnectionKey& /*key*/, const wirepeek::HttpTransaction& txn) {
        http_txns.push_back(txn);
      },
      nullptr);

  auto key = MakeConnectionKey(MakeIpv4(192, 168, 1, 1), 12345, MakeIpv4(192, 168, 1, 2), 80);

  handler.OnStreamEvent(MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kOpen),
                        MakeTs(1));

  // Send unknown data — should not crash even with null callback.
  auto unknown = ToBytes("BINARY\x00\x01\x02");
  handler.OnStreamEvent(MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kData, unknown,
                                        wirepeek::StreamDirection::kClientToServer),
                        MakeTs(2));

  // Just verify no crash occurs.
  EXPECT_TRUE(true);
}

// ── Edge Case: Close Before Protocol Detection ────────────────────────────────

TEST(ProtocolHandlerTest, CloseBeforeProtocolDetection) {
  std::vector<wirepeek::HttpTransaction> http_txns;
  std::vector<std::pair<wirepeek::StreamDirection, size_t>> raw_calls;

  wirepeek::protocol::ProtocolHandler handler(
      [&](const wirepeek::ConnectionKey& /*key*/, const wirepeek::HttpTransaction& txn) {
        http_txns.push_back(txn);
      },
      [&](const wirepeek::ConnectionKey& /*key*/, wirepeek::StreamDirection dir,
          std::span<const uint8_t> data) { raw_calls.push_back({dir, data.size()}); });

  auto key = MakeConnectionKey(MakeIpv4(192, 168, 1, 1), 12345, MakeIpv4(192, 168, 1, 2), 80);

  // Open stream.
  handler.OnStreamEvent(MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kOpen),
                        MakeTs(1));

  // Close immediately without any data.
  handler.OnStreamEvent(MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kClose),
                        MakeTs(2));

  // Should not have any transactions or raw calls.
  EXPECT_TRUE(http_txns.empty());
  EXPECT_TRUE(raw_calls.empty());
}

// ── Edge Case: Multiple Data Events Before Close ────────────────────────────

TEST(ProtocolHandlerTest, MultipleDataEventsBeforeClose) {
  std::vector<wirepeek::HttpTransaction> http_txns;
  wirepeek::protocol::ProtocolHandler handler(
      [&](const wirepeek::ConnectionKey& /*key*/, const wirepeek::HttpTransaction& txn) {
        http_txns.push_back(txn);
      });

  auto key = MakeConnectionKey(MakeIpv4(192, 168, 1, 1), 12345, MakeIpv4(192, 168, 1, 2), 80);

  handler.OnStreamEvent(MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kOpen),
                        MakeTs(1));

  // Fragment 1: Part of request.
  auto frag1 = ToBytes("GET / HTTP/1.1\r\n");
  handler.OnStreamEvent(MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kData, frag1,
                                        wirepeek::StreamDirection::kClientToServer),
                        MakeTs(2));

  // Fragment 2: Headers.
  auto frag2 = ToBytes("Host: example.com\r\n\r\n");
  handler.OnStreamEvent(MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kData, frag2,
                                        wirepeek::StreamDirection::kClientToServer),
                        MakeTs(3));

  // Response in one chunk.
  auto resp = ToBytes("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nOK!");
  handler.OnStreamEvent(MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kData, resp,
                                        wirepeek::StreamDirection::kServerToClient),
                        MakeTs(4));

  // Should have parsed the complete transaction despite fragmentation.
  ASSERT_EQ(http_txns.size(), 1u);
  EXPECT_EQ(http_txns[0].request.method, "GET");
  EXPECT_EQ(http_txns[0].request.url, "/");
  EXPECT_EQ(http_txns[0].response.status_code, 200);
  EXPECT_EQ(http_txns[0].response.body_size, 3u);
}

// ── Edge Case: Bidirectional Data Interleaving ────────────────────────────────

TEST(ProtocolHandlerTest, BidirectionalInterleaving) {
  std::vector<wirepeek::HttpTransaction> http_txns;
  wirepeek::protocol::ProtocolHandler handler(
      [&](const wirepeek::ConnectionKey& /*key*/, const wirepeek::HttpTransaction& txn) {
        http_txns.push_back(txn);
      });

  auto key = MakeConnectionKey(MakeIpv4(192, 168, 1, 1), 12345, MakeIpv4(192, 168, 1, 2), 80);

  handler.OnStreamEvent(MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kOpen),
                        MakeTs(1));

  // Client→Server: Request.
  auto req = ToBytes("POST /data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello");
  handler.OnStreamEvent(MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kData, req,
                                        wirepeek::StreamDirection::kClientToServer),
                        MakeTs(2));

  // Server→Client: Partial response (headers only).
  auto resp_hdr = ToBytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
  handler.OnStreamEvent(MakeStreamEvent(key, wirepeek::dissector::StreamEventType::kData, resp_hdr,
                                        wirepeek::StreamDirection::kServerToClient),
                        MakeTs(3));

  // Should have emitted transaction.
  ASSERT_EQ(http_txns.size(), 1u);
  EXPECT_EQ(http_txns[0].request.method, "POST");
  EXPECT_EQ(http_txns[0].response.status_code, 200);
}

}  // namespace
}  // namespace wirepeek::protocol
