// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/detector.h>

#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace wirepeek::protocol {
namespace {

std::vector<uint8_t> ToBytes(const std::string& s) {
  return {s.begin(), s.end()};
}

TEST(DetectorTest, HttpGetRequest) {
  auto data = ToBytes("GET /index.html HTTP/1.1\r\n");
  EXPECT_EQ(DetectProtocol(data), AppProtocol::kHttp1);
}

TEST(DetectorTest, HttpPostRequest) {
  auto data = ToBytes("POST /api/users HTTP/1.1\r\n");
  EXPECT_EQ(DetectProtocol(data), AppProtocol::kHttp1);
}

TEST(DetectorTest, HttpPutRequest) {
  auto data = ToBytes("PUT /resource HTTP/1.1\r\n");
  EXPECT_EQ(DetectProtocol(data), AppProtocol::kHttp1);
}

TEST(DetectorTest, HttpDeleteRequest) {
  auto data = ToBytes("DELETE /items/42 HTTP/1.1\r\n");
  EXPECT_EQ(DetectProtocol(data), AppProtocol::kHttp1);
}

TEST(DetectorTest, HttpHeadRequest) {
  auto data = ToBytes("HEAD / HTTP/1.1\r\n");
  EXPECT_EQ(DetectProtocol(data), AppProtocol::kHttp1);
}

TEST(DetectorTest, HttpOptionsRequest) {
  auto data = ToBytes("OPTIONS * HTTP/1.1\r\n");
  EXPECT_EQ(DetectProtocol(data), AppProtocol::kHttp1);
}

TEST(DetectorTest, HttpPatchRequest) {
  auto data = ToBytes("PATCH /items/42 HTTP/1.1\r\n");
  EXPECT_EQ(DetectProtocol(data), AppProtocol::kHttp1);
}

TEST(DetectorTest, HttpResponse) {
  auto data = ToBytes("HTTP/1.1 200 OK\r\n");
  EXPECT_EQ(DetectProtocol(data), AppProtocol::kHttp1);
}

TEST(DetectorTest, TlsHandshake) {
  // TLS 1.2 ClientHello record.
  std::vector<uint8_t> data = {0x16, 0x03, 0x01, 0x00, 0xFF};
  EXPECT_EQ(DetectProtocol(data), AppProtocol::kTls);
}

TEST(DetectorTest, TlsHandshake13) {
  // TLS 1.3.
  std::vector<uint8_t> data = {0x16, 0x03, 0x03, 0x00, 0xFF};
  EXPECT_EQ(DetectProtocol(data), AppProtocol::kTls);
}

TEST(DetectorTest, Http2Preface) {
  auto data = ToBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
  EXPECT_EQ(DetectProtocol(data), AppProtocol::kHttp2);
}

TEST(DetectorTest, UnknownProtocol) {
  std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};
  EXPECT_EQ(DetectProtocol(data), AppProtocol::kUnknown);
}

TEST(DetectorTest, TooShort) {
  std::vector<uint8_t> data = {0x47, 0x45};  // "GE" — not enough to detect.
  EXPECT_EQ(DetectProtocol(data), AppProtocol::kUnknown);
}

TEST(DetectorTest, EmptyData) {
  std::vector<uint8_t> data;
  EXPECT_EQ(DetectProtocol(data), AppProtocol::kUnknown);
}

}  // namespace
}  // namespace wirepeek::protocol
