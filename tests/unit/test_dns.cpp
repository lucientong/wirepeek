// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/dns.h>

#include <cstdint>
#include <gtest/gtest.h>
#include <vector>

namespace wirepeek::protocol {
namespace {

// Helper: build a simple DNS query packet for "example.com" type A.
std::vector<uint8_t> MakeDnsQuery(uint16_t id = 0x1234) {
  std::vector<uint8_t> pkt;
  // Header (12 bytes).
  pkt.push_back(id >> 8);
  pkt.push_back(id & 0xFF);
  pkt.insert(pkt.end(), {0x01, 0x00});  // Flags: standard query, recursion desired
  pkt.insert(pkt.end(), {0x00, 0x01});  // QDCOUNT = 1
  pkt.insert(pkt.end(), {0x00, 0x00});  // ANCOUNT = 0
  pkt.insert(pkt.end(), {0x00, 0x00});  // NSCOUNT = 0
  pkt.insert(pkt.end(), {0x00, 0x00});  // ARCOUNT = 0
  // Question: "example.com" type A class IN
  pkt.insert(pkt.end(), {7, 'e', 'x', 'a', 'm', 'p', 'l', 'e'});
  pkt.insert(pkt.end(), {3, 'c', 'o', 'm'});
  pkt.push_back(0);                     // End of name
  pkt.insert(pkt.end(), {0x00, 0x01});  // QTYPE = A
  pkt.insert(pkt.end(), {0x00, 0x01});  // QCLASS = IN
  return pkt;
}

// Build a DNS response with one A record answer.
std::vector<uint8_t> MakeDnsResponse(uint16_t id = 0x1234) {
  std::vector<uint8_t> pkt;
  pkt.push_back(id >> 8);
  pkt.push_back(id & 0xFF);
  pkt.insert(pkt.end(), {0x81, 0x80});  // Flags: response, recursion desired+available
  pkt.insert(pkt.end(), {0x00, 0x01});  // QDCOUNT = 1
  pkt.insert(pkt.end(), {0x00, 0x01});  // ANCOUNT = 1
  pkt.insert(pkt.end(), {0x00, 0x00});  // NSCOUNT
  pkt.insert(pkt.end(), {0x00, 0x00});  // ARCOUNT
  // Question section (same as query).
  pkt.insert(pkt.end(), {7, 'e', 'x', 'a', 'm', 'p', 'l', 'e'});
  pkt.insert(pkt.end(), {3, 'c', 'o', 'm'});
  pkt.push_back(0);
  pkt.insert(pkt.end(), {0x00, 0x01});  // QTYPE = A
  pkt.insert(pkt.end(), {0x00, 0x01});  // QCLASS = IN
  // Answer section: "example.com" A 93.184.216.34
  pkt.insert(pkt.end(), {0xC0, 0x0C});              // Name pointer to offset 12
  pkt.insert(pkt.end(), {0x00, 0x01});              // TYPE = A
  pkt.insert(pkt.end(), {0x00, 0x01});              // CLASS = IN
  pkt.insert(pkt.end(), {0x00, 0x00, 0x00, 0x3C});  // TTL = 60
  pkt.insert(pkt.end(), {0x00, 0x04});              // RDLENGTH = 4
  pkt.insert(pkt.end(), {93, 184, 216, 34});        // RDATA
  return pkt;
}

TEST(DnsTest, ParseQuery) {
  auto pkt = MakeDnsQuery(0xABCD);
  auto result = ParseDnsQuery(pkt);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->id, 0xABCD);
  EXPECT_EQ(result->name, "example.com");
  EXPECT_EQ(result->type, 1);  // A record
}

TEST(DnsTest, ParseResponse) {
  auto pkt = MakeDnsResponse(0x1234);
  auto result = ParseDnsResponse(pkt);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->id, 0x1234);
  EXPECT_EQ(result->name, "example.com");
  EXPECT_EQ(result->rcode, 0);  // NoError
  ASSERT_EQ(result->answers.size(), 1u);
  EXPECT_EQ(result->answers[0], "93.184.216.34");
}

TEST(DnsTest, QueryNotResponse) {
  auto pkt = MakeDnsQuery();
  EXPECT_FALSE(ParseDnsResponse(pkt).has_value());
}

TEST(DnsTest, ResponseNotQuery) {
  auto pkt = MakeDnsResponse();
  EXPECT_FALSE(ParseDnsQuery(pkt).has_value());
}

TEST(DnsTest, TruncatedPacket) {
  std::vector<uint8_t> pkt(6, 0);  // Too short for DNS header.
  EXPECT_FALSE(ParseDnsQuery(pkt).has_value());
  EXPECT_FALSE(ParseDnsResponse(pkt).has_value());
}

TEST(DnsTest, LooksDnsShaped) {
  auto query = MakeDnsQuery();
  EXPECT_TRUE(LooksDnsShaped(query));

  auto response = MakeDnsResponse();
  EXPECT_TRUE(LooksDnsShaped(response));

  std::vector<uint8_t> random = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  // Random data with qdcount=0 should fail.
  EXPECT_FALSE(LooksDnsShaped(random));
}

}  // namespace
}  // namespace wirepeek::protocol
