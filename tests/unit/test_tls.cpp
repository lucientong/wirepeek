// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/tls.h>

#include <cstdint>
#include <gtest/gtest.h>
#include <vector>

namespace wirepeek::protocol {
namespace {

// Build a minimal TLS ClientHello with SNI extension.
std::vector<uint8_t> MakeClientHello(const std::string& sni = "example.com") {
  std::vector<uint8_t> pkt;

  // We'll build the inner content first, then wrap with record + handshake headers.
  std::vector<uint8_t> hello;

  // Client version: TLS 1.2 (0x0303).
  hello.insert(hello.end(), {0x03, 0x03});
  // Random (32 bytes).
  for (int i = 0; i < 32; ++i)
    hello.push_back(0xAA);
  // Session ID length: 0.
  hello.push_back(0x00);
  // Cipher suites: length=2, one suite.
  hello.insert(hello.end(), {0x00, 0x02, 0xC0, 0x2F});
  // Compression methods: length=1, null.
  hello.insert(hello.end(), {0x01, 0x00});

  // Extensions.
  std::vector<uint8_t> exts;
  // SNI extension.
  {
    std::vector<uint8_t> sni_ext;
    // Server name list length.
    uint16_t name_len = static_cast<uint16_t>(sni.size());
    uint16_t list_len = name_len + 3;
    sni_ext.push_back(list_len >> 8);
    sni_ext.push_back(list_len & 0xFF);
    sni_ext.push_back(0x00);  // host_name type
    sni_ext.push_back(name_len >> 8);
    sni_ext.push_back(name_len & 0xFF);
    sni_ext.insert(sni_ext.end(), sni.begin(), sni.end());

    // Extension header: type=0x0000, length.
    exts.insert(exts.end(), {0x00, 0x00});
    uint16_t ext_len = static_cast<uint16_t>(sni_ext.size());
    exts.push_back(ext_len >> 8);
    exts.push_back(ext_len & 0xFF);
    exts.insert(exts.end(), sni_ext.begin(), sni_ext.end());
  }

  // Extensions total length.
  uint16_t ext_total = static_cast<uint16_t>(exts.size());
  hello.push_back(ext_total >> 8);
  hello.push_back(ext_total & 0xFF);
  hello.insert(hello.end(), exts.begin(), exts.end());

  // Handshake header: type=1 (ClientHello), length (3 bytes).
  uint32_t hs_len = static_cast<uint32_t>(hello.size());
  std::vector<uint8_t> handshake;
  handshake.push_back(0x01);  // ClientHello
  handshake.push_back((hs_len >> 16) & 0xFF);
  handshake.push_back((hs_len >> 8) & 0xFF);
  handshake.push_back(hs_len & 0xFF);
  handshake.insert(handshake.end(), hello.begin(), hello.end());

  // TLS record header: type=22, version=0x0301, length.
  uint16_t rec_len = static_cast<uint16_t>(handshake.size());
  pkt.push_back(0x16);                  // Handshake
  pkt.insert(pkt.end(), {0x03, 0x01});  // TLS 1.0 (record layer)
  pkt.push_back(rec_len >> 8);
  pkt.push_back(rec_len & 0xFF);
  pkt.insert(pkt.end(), handshake.begin(), handshake.end());

  return pkt;
}

// Build a minimal TLS ServerHello.
std::vector<uint8_t> MakeServerHello() {
  std::vector<uint8_t> hello;
  // Server version: TLS 1.2.
  hello.insert(hello.end(), {0x03, 0x03});
  // Random (32 bytes).
  for (int i = 0; i < 32; ++i)
    hello.push_back(0xBB);
  // Session ID length: 0.
  hello.push_back(0x00);
  // Cipher suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F.
  hello.insert(hello.end(), {0xC0, 0x2F});
  // Compression method: null.
  hello.push_back(0x00);

  // Handshake header.
  uint32_t hs_len = static_cast<uint32_t>(hello.size());
  std::vector<uint8_t> handshake;
  handshake.push_back(0x02);  // ServerHello
  handshake.push_back((hs_len >> 16) & 0xFF);
  handshake.push_back((hs_len >> 8) & 0xFF);
  handshake.push_back(hs_len & 0xFF);
  handshake.insert(handshake.end(), hello.begin(), hello.end());

  // TLS record.
  std::vector<uint8_t> pkt;
  uint16_t rec_len = static_cast<uint16_t>(handshake.size());
  pkt.push_back(0x16);
  pkt.insert(pkt.end(), {0x03, 0x03});
  pkt.push_back(rec_len >> 8);
  pkt.push_back(rec_len & 0xFF);
  pkt.insert(pkt.end(), handshake.begin(), handshake.end());
  return pkt;
}

TEST(TlsTest, ParseClientHelloSNI) {
  auto pkt = MakeClientHello("api.example.com");
  auto result = ParseTlsClientHello(pkt);

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_client_hello);
  EXPECT_EQ(result->sni, "api.example.com");
  EXPECT_EQ(result->version, 0x0303);  // TLS 1.2
}

TEST(TlsTest, ParseServerHello) {
  auto pkt = MakeServerHello();
  auto result = ParseTlsServerHello(pkt);

  ASSERT_TRUE(result.has_value());
  EXPECT_FALSE(result->is_client_hello);
  EXPECT_EQ(result->cipher_suite, "0xC02F");
  EXPECT_EQ(result->version, 0x0303);
}

TEST(TlsTest, ClientHelloNotServerHello) {
  auto pkt = MakeClientHello();
  EXPECT_FALSE(ParseTlsServerHello(pkt).has_value());
}

TEST(TlsTest, ServerHelloNotClientHello) {
  auto pkt = MakeServerHello();
  EXPECT_FALSE(ParseTlsClientHello(pkt).has_value());
}

TEST(TlsTest, TruncatedPacket) {
  std::vector<uint8_t> pkt = {0x16, 0x03, 0x01, 0x00};
  EXPECT_FALSE(ParseTlsClientHello(pkt).has_value());
}

TEST(TlsTest, NonTlsPacket) {
  std::vector<uint8_t> pkt(50, 0x00);
  EXPECT_FALSE(ParseTlsClientHello(pkt).has_value());
}

}  // namespace
}  // namespace wirepeek::protocol
