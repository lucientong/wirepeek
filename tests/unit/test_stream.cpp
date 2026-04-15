// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/stream.h>

#include <gtest/gtest.h>
#include <unordered_map>

namespace wirepeek {
namespace {

ConnectionKey MakeKey(uint8_t last_src_byte, uint16_t src_port, uint8_t last_dst_byte,
                      uint16_t dst_port, uint8_t protocol = 6) {
  ConnectionKey key;
  key.src_ip[3] = last_src_byte;
  key.src_port = src_port;
  key.dst_ip[3] = last_dst_byte;
  key.dst_port = dst_port;
  key.protocol = protocol;
  key.ip_version = 4;
  return key;
}

TEST(ConnectionKeyTest, EqualKeysAreEqual) {
  auto a = MakeKey(1, 80, 2, 443);
  auto b = MakeKey(1, 80, 2, 443);
  EXPECT_EQ(a, b);
}

TEST(ConnectionKeyTest, DifferentPortsNotEqual) {
  auto a = MakeKey(1, 80, 2, 443);
  auto b = MakeKey(1, 81, 2, 443);
  EXPECT_NE(a, b);
}

TEST(ConnectionKeyTest, DifferentIpsNotEqual) {
  auto a = MakeKey(1, 80, 2, 443);
  auto b = MakeKey(1, 80, 3, 443);
  EXPECT_NE(a, b);
}

TEST(ConnectionKeyTest, DifferentProtocolNotEqual) {
  auto a = MakeKey(1, 80, 2, 443, 6);   // TCP
  auto b = MakeKey(1, 80, 2, 443, 17);  // UDP
  EXPECT_NE(a, b);
}

TEST(ConnectionKeyTest, HashConsistency) {
  auto a = MakeKey(1, 80, 2, 443);
  auto b = MakeKey(1, 80, 2, 443);
  std::hash<ConnectionKey> hasher;
  EXPECT_EQ(hasher(a), hasher(b));
}

TEST(ConnectionKeyTest, HashDifference) {
  auto a = MakeKey(1, 80, 2, 443);
  auto b = MakeKey(1, 80, 2, 444);
  std::hash<ConnectionKey> hasher;
  // Different keys should (very likely) produce different hashes.
  EXPECT_NE(hasher(a), hasher(b));
}

TEST(ConnectionKeyTest, UsableInUnorderedMap) {
  std::unordered_map<ConnectionKey, int> map;
  auto key1 = MakeKey(10, 8080, 20, 80);
  auto key2 = MakeKey(10, 8081, 20, 80);

  map[key1] = 1;
  map[key2] = 2;

  EXPECT_EQ(map.size(), 2u);
  EXPECT_EQ(map[key1], 1);
  EXPECT_EQ(map[key2], 2);

  // Lookup with equal key.
  auto key1_copy = MakeKey(10, 8080, 20, 80);
  EXPECT_EQ(map[key1_copy], 1);
}

}  // namespace
}  // namespace wirepeek
