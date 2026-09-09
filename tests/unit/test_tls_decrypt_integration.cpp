// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/dissector/tcp_reassembler.h>
#include <wirepeek/protocol/protocol_handler.h>
#include <wirepeek/protocol/tls.h>
#include <wirepeek/protocol/tls_cipher.h>
#include <wirepeek/protocol/tls_crypto.h>
#include <wirepeek/protocol/tls_keylog.h>
#include <wirepeek/protocol/tls_record.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

#if defined(WIREPEEK_ENABLE_TLS_DECRYPT)

#include <openssl/evp.h>

namespace wirepeek::protocol {
namespace {

std::vector<uint8_t> WrapRecord(TlsContentType type, uint16_t version,
                                std::span<const uint8_t> payload) {
  std::vector<uint8_t> out;
  out.push_back(static_cast<uint8_t>(type));
  out.push_back(static_cast<uint8_t>(version >> 8));
  out.push_back(static_cast<uint8_t>(version & 0xFF));
  out.push_back(static_cast<uint8_t>(payload.size() >> 8));
  out.push_back(static_cast<uint8_t>(payload.size() & 0xFF));
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

std::vector<uint8_t> MakeClientHelloRecord(const std::array<uint8_t, 32>& client_random,
                                           const std::string& sni) {
  std::vector<uint8_t> body;
  body.insert(body.end(), {0x03, 0x03});
  body.insert(body.end(), client_random.begin(), client_random.end());
  body.push_back(0x00);
  body.insert(body.end(), {0x00, 0x04, 0x13, 0x01, 0xC0, 0x2F});
  body.insert(body.end(), {0x01, 0x00});

  std::vector<uint8_t> exts;
  {
    std::vector<uint8_t> sni_ext;
    const uint16_t name_len = static_cast<uint16_t>(sni.size());
    const uint16_t list_len = static_cast<uint16_t>(name_len + 3);
    sni_ext.push_back(static_cast<uint8_t>(list_len >> 8));
    sni_ext.push_back(static_cast<uint8_t>(list_len & 0xFF));
    sni_ext.push_back(0x00);
    sni_ext.push_back(static_cast<uint8_t>(name_len >> 8));
    sni_ext.push_back(static_cast<uint8_t>(name_len & 0xFF));
    sni_ext.insert(sni_ext.end(), sni.begin(), sni.end());
    exts.insert(exts.end(), {0x00, 0x00});
    exts.push_back(static_cast<uint8_t>(sni_ext.size() >> 8));
    exts.push_back(static_cast<uint8_t>(sni_ext.size() & 0xFF));
    exts.insert(exts.end(), sni_ext.begin(), sni_ext.end());
  }
  {
    const std::string proto = "http/1.1";
    std::vector<uint8_t> alpn;
    alpn.push_back(0x00);
    alpn.push_back(static_cast<uint8_t>(proto.size() + 1));
    alpn.push_back(static_cast<uint8_t>(proto.size()));
    alpn.insert(alpn.end(), proto.begin(), proto.end());
    exts.insert(exts.end(), {0x00, 0x10});
    exts.push_back(static_cast<uint8_t>(alpn.size() >> 8));
    exts.push_back(static_cast<uint8_t>(alpn.size() & 0xFF));
    exts.insert(exts.end(), alpn.begin(), alpn.end());
  }
  {
    std::vector<uint8_t> versions = {0x02, 0x03, 0x04};
    exts.insert(exts.end(), {0x00, 0x2B, 0x00, static_cast<uint8_t>(versions.size())});
    exts.insert(exts.end(), versions.begin(), versions.end());
  }

  body.push_back(static_cast<uint8_t>(exts.size() >> 8));
  body.push_back(static_cast<uint8_t>(exts.size() & 0xFF));
  body.insert(body.end(), exts.begin(), exts.end());

  std::vector<uint8_t> hs;
  hs.push_back(0x01);
  hs.push_back(static_cast<uint8_t>((body.size() >> 16) & 0xFF));
  hs.push_back(static_cast<uint8_t>((body.size() >> 8) & 0xFF));
  hs.push_back(static_cast<uint8_t>(body.size() & 0xFF));
  hs.insert(hs.end(), body.begin(), body.end());
  return WrapRecord(TlsContentType::kHandshake, 0x0301, hs);
}

std::vector<uint8_t> MakeServerHelloRecord(const std::array<uint8_t, 32>& server_random) {
  std::vector<uint8_t> body;
  body.insert(body.end(), {0x03, 0x03});
  body.insert(body.end(), server_random.begin(), server_random.end());
  body.push_back(0x00);
  body.insert(body.end(), {0x13, 0x01});
  body.push_back(0x00);
  std::vector<uint8_t> exts = {0x00, 0x2B, 0x00, 0x02, 0x03, 0x04};
  body.push_back(static_cast<uint8_t>(exts.size() >> 8));
  body.push_back(static_cast<uint8_t>(exts.size() & 0xFF));
  body.insert(body.end(), exts.begin(), exts.end());

  std::vector<uint8_t> hs;
  hs.push_back(0x02);
  hs.push_back(static_cast<uint8_t>((body.size() >> 16) & 0xFF));
  hs.push_back(static_cast<uint8_t>((body.size() >> 8) & 0xFF));
  hs.push_back(static_cast<uint8_t>(body.size() & 0xFF));
  hs.insert(hs.end(), body.begin(), body.end());
  return WrapRecord(TlsContentType::kHandshake, 0x0303, hs);
}

std::vector<uint8_t> EncryptTls13AppData(const TlsCipherSuiteInfo& suite,
                                         std::span<const uint8_t> traffic_secret, uint64_t seq,
                                         std::span<const uint8_t> plaintext,
                                         TlsContentType inner_type) {
  auto keys = Tls13DeriveTrafficKeys(suite, traffic_secret);
  EXPECT_TRUE(keys.has_value());

  std::vector<uint8_t> inner(plaintext.begin(), plaintext.end());
  inner.push_back(static_cast<uint8_t>(inner_type));

  std::array<uint8_t, 12> nonce{};
  std::copy_n(keys->iv.begin(), 12, nonce.begin());
  for (int i = 0; i < 8; ++i)
    nonce[static_cast<size_t>(11 - i)] ^= static_cast<uint8_t>((seq >> (i * 8)) & 0xFF);

  const uint16_t record_len = static_cast<uint16_t>(inner.size() + suite.tag_len);
  std::vector<uint8_t> aad = {0x17, 0x03, 0x03, static_cast<uint8_t>(record_len >> 8),
                              static_cast<uint8_t>(record_len & 0xFF)};

  EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, suite.openssl_cipher, nullptr);
  EXPECT_NE(cipher, nullptr);
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  EXPECT_NE(ctx, nullptr);
  EXPECT_EQ(EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr), 1);
  EXPECT_EQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr), 1);
  EXPECT_EQ(EVP_EncryptInit_ex(ctx, nullptr, nullptr, keys->key.data(), nonce.data()), 1);

  int len = 0;
  EXPECT_EQ(EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())), 1);
  std::vector<uint8_t> ciphertext(inner.size());
  EXPECT_EQ(EVP_EncryptUpdate(ctx, ciphertext.data(), &len, inner.data(),
                              static_cast<int>(inner.size())),
            1);
  int final_len = 0;
  EXPECT_EQ(EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &final_len), 1);
  std::vector<uint8_t> tag(suite.tag_len);
  EXPECT_EQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(suite.tag_len),
                                tag.data()),
            1);
  EVP_CIPHER_CTX_free(ctx);
  EVP_CIPHER_free(cipher);

  ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
  return WrapRecord(TlsContentType::kApplicationData, 0x0303, ciphertext);
}

ConnectionKey MakeKey() {
  ConnectionKey key;
  key.ip_version = 4;
  key.protocol = 6;
  key.src_port = 12345;
  key.dst_port = 443;
  key.src_ip[0] = 127;
  key.src_ip[3] = 1;
  key.dst_ip[0] = 127;
  key.dst_ip[3] = 2;
  return key;
}

void Feed(ProtocolHandler& handler, const ConnectionKey& key, StreamDirection dir,
          const std::vector<uint8_t>& data) {
  dissector::StreamEvent event{
      .key = key,
      .direction = dir,
      .type = dissector::StreamEventType::kData,
      .data = data,
      .timestamp = Timestamp{},
  };
  handler.OnStreamEvent(event, event.timestamp);
}

TEST(TlsDecryptIntegrationTest, RecoversHttp1FromTls13AppData) {
  std::array<uint8_t, 32> client_random{};
  std::array<uint8_t, 32> server_random{};
  for (int i = 0; i < 32; ++i) {
    client_random[static_cast<size_t>(i)] = static_cast<uint8_t>(0x10 + i);
    server_random[static_cast<size_t>(i)] = static_cast<uint8_t>(0x40 + i);
  }
  const std::vector<uint8_t> client_secret(32, 0xC1);
  const std::vector<uint8_t> server_secret(32, 0xD2);
  const auto random_hex = HexEncode(client_random);

  auto keylog = std::make_shared<TlsKeyLog>();
  ASSERT_TRUE(keylog->ParseLine("CLIENT_TRAFFIC_SECRET_0 " + random_hex + " " +
                                HexEncode(client_secret)));
  ASSERT_TRUE(keylog->ParseLine("SERVER_TRAFFIC_SECRET_0 " + random_hex + " " +
                                HexEncode(server_secret)));

  std::optional<HttpTransaction> seen;
  ProtocolHandler handler([&](const ConnectionKey&, const AppEvent& event) {
    if (const auto* txn = std::get_if<HttpTransaction>(&event))
      seen = *txn;
  });
  handler.SetTlsKeyLog(keylog);

  const auto key = MakeKey();
  dissector::StreamEvent open{
      .key = key,
      .direction = StreamDirection::kClientToServer,
      .type = dissector::StreamEventType::kOpen,
      .data = {},
      .timestamp = Timestamp{},
  };
  handler.OnStreamEvent(open, Timestamp{});

  Feed(handler, key, StreamDirection::kClientToServer,
       MakeClientHelloRecord(client_random, "local.test"));
  Feed(handler, key, StreamDirection::kServerToClient, MakeServerHelloRecord(server_random));

  auto suite = LookupCipherSuite(0x1301);
  ASSERT_TRUE(suite);
  const std::string req =
      "GET /hello HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n";
  const std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
  const auto req_bytes = std::vector<uint8_t>(req.begin(), req.end());
  const auto resp_bytes = std::vector<uint8_t>(resp.begin(), resp.end());

  Feed(handler, key, StreamDirection::kClientToServer,
       EncryptTls13AppData(*suite, client_secret, 0, req_bytes, TlsContentType::kApplicationData));
  Feed(handler, key, StreamDirection::kServerToClient,
       EncryptTls13AppData(*suite, server_secret, 0, resp_bytes, TlsContentType::kApplicationData));

  ASSERT_TRUE(seen.has_value());
  EXPECT_TRUE(seen->via_tls);
  EXPECT_TRUE(seen->decrypted);
  EXPECT_EQ(seen->sni, "local.test");
  EXPECT_EQ(seen->request.method, "GET");
  EXPECT_EQ(seen->request.url, "/hello");
  EXPECT_EQ(seen->response.status_code, 200);
  EXPECT_TRUE(seen->complete);
}

TEST(TlsDecryptIntegrationTest, MissingKeylogEmitsHandshakeOnly) {
  std::array<uint8_t, 32> client_random{};
  client_random.fill(0x22);
  std::array<uint8_t, 32> server_random{};
  server_random.fill(0x33);

  int tls_events = 0;
  int http_events = 0;
  ProtocolHandler handler([&](const ConnectionKey&, const AppEvent& event) {
    if (std::holds_alternative<TlsHandshakeInfo>(event))
      ++tls_events;
    if (std::holds_alternative<HttpTransaction>(event))
      ++http_events;
  });

  const auto key = MakeKey();
  dissector::StreamEvent open{
      .key = key,
      .direction = StreamDirection::kClientToServer,
      .type = dissector::StreamEventType::kOpen,
      .data = {},
      .timestamp = Timestamp{},
  };
  handler.OnStreamEvent(open, Timestamp{});
  Feed(handler, key, StreamDirection::kClientToServer,
       MakeClientHelloRecord(client_random, "nomatch.test"));
  Feed(handler, key, StreamDirection::kServerToClient, MakeServerHelloRecord(server_random));
  EXPECT_GE(tls_events, 1);
  EXPECT_EQ(http_events, 0);
}

}  // namespace
}  // namespace wirepeek::protocol

#endif
