// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/tls.h>
#include <wirepeek/protocol/tls_record.h>

#include <cstdint>
#include <gtest/gtest.h>
#include <span>
#include <vector>

namespace wirepeek::protocol {
namespace {

std::vector<uint8_t> MakeRecord(uint8_t type, uint16_t version, std::span<const uint8_t> payload) {
  std::vector<uint8_t> out;
  out.push_back(type);
  out.push_back(static_cast<uint8_t>(version >> 8));
  out.push_back(static_cast<uint8_t>(version & 0xFF));
  out.push_back(static_cast<uint8_t>(payload.size() >> 8));
  out.push_back(static_cast<uint8_t>(payload.size() & 0xFF));
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

TEST(TlsRecordTest, FramesAcrossSegments) {
  const std::vector<uint8_t> payload = {0x01, 0x02, 0x03, 0x04};
  auto record = MakeRecord(22, 0x0303, payload);

  TlsRecordFramer framer;
  auto first = framer.Feed(std::span(record).first(3));
  EXPECT_TRUE(first.empty());
  auto second = framer.Feed(std::span(record).subspan(3));
  ASSERT_EQ(second.size(), 1u);
  EXPECT_EQ(second[0].type, TlsContentType::kHandshake);
  EXPECT_EQ(second[0].payload, payload);
}

TEST(TlsRecordTest, MultipleRecordsInOneBuffer) {
  const std::vector<uint8_t> a = {0xAA};
  const std::vector<uint8_t> b = {0xBB, 0xCC};
  auto bytes = MakeRecord(23, 0x0303, a);
  auto second = MakeRecord(20, 0x0303, b);
  bytes.insert(bytes.end(), second.begin(), second.end());

  TlsRecordFramer framer;
  auto records = framer.Feed(bytes);
  ASSERT_EQ(records.size(), 2u);
  EXPECT_EQ(records[0].type, TlsContentType::kApplicationData);
  EXPECT_EQ(records[1].type, TlsContentType::kChangeCipherSpec);
}

TEST(TlsRecordTest, RejectsOversizedRecord) {
  std::vector<uint8_t> header = {22, 0x03, 0x03, 0xFF, 0xFF};
  TlsRecordFramer framer;
  auto records = framer.Feed(header);
  EXPECT_TRUE(records.empty());
  EXPECT_TRUE(framer.Failed());
}

TEST(TlsRecordTest, IndependentDirectionBuffers) {
  TlsRecordFramer client;
  TlsRecordFramer server;
  const std::vector<uint8_t> payload = {0x01};
  auto record = MakeRecord(22, 0x0303, payload);
  EXPECT_TRUE(client.Feed(std::span(record).first(2)).empty());
  auto done = server.Feed(record);
  ASSERT_EQ(done.size(), 1u);
  EXPECT_FALSE(client.Failed());
}

TEST(TlsHandshakeReassemblerTest, SpansRecords) {
  std::vector<uint8_t> body(10, 0x11);
  std::vector<uint8_t> message;
  message.push_back(0x01);
  message.push_back(0x00);
  message.push_back(0x00);
  message.push_back(static_cast<uint8_t>(body.size()));
  message.insert(message.end(), body.begin(), body.end());

  TlsHandshakeReassembler reasm;
  auto part1 = reasm.Feed(std::span(message).first(5));
  EXPECT_TRUE(part1.empty());
  auto part2 = reasm.Feed(std::span(message).subspan(5));
  ASSERT_EQ(part2.size(), 1u);
  EXPECT_EQ(part2[0].type, TlsHandshakeType::kClientHello);
  EXPECT_EQ(part2[0].body, body);
}

TEST(TlsParseTest, ExtractsClientRandom) {
  // Minimal ClientHello built like unit fixture in test_tls.cpp path via ParseTlsClientHelloBody.
  std::vector<uint8_t> body;
  body.insert(body.end(), {0x03, 0x03});
  for (int i = 0; i < 32; ++i)
    body.push_back(static_cast<uint8_t>(i));
  body.push_back(0x00);  // session id len
  body.insert(body.end(), {0x00, 0x02, 0xC0, 0x2F});
  body.insert(body.end(), {0x01, 0x00});  // compression
  body.insert(body.end(), {0x00, 0x00});  // extensions

  auto info = ParseTlsClientHelloBody(body);
  ASSERT_TRUE(info);
  EXPECT_TRUE(info->has_client_random);
  EXPECT_EQ(info->client_random[0], 0);
  EXPECT_EQ(info->client_random[31], 31);
  EXPECT_EQ(HexEncode(info->client_random).size(), 64u);
}

}  // namespace
}  // namespace wirepeek::protocol
