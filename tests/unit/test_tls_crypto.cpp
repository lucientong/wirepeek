// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/tls_cipher.h>
#include <wirepeek/protocol/tls_crypto.h>
#include <wirepeek/protocol/tls_keylog.h>

#include <cstdio>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#if defined(WIREPEEK_ENABLE_TLS_DECRYPT)
#include <openssl/evp.h>
#endif

namespace wirepeek::protocol {
namespace {

std::string MakeRandomHex() {
  return std::string(64, 'a');
}

TEST(TlsKeyLogLifecycleTest, IncrementalRefreshAndTruncate) {
  const std::string path = "tls_keylog_refresh_test.txt";
  std::remove(path.c_str());

  {
    std::ofstream out(path);
    out << "CLIENT_RANDOM " << MakeRandomHex() << " " << std::string(96, '1') << "\n";
  }

  TlsKeyLog keylog;
  ASSERT_TRUE(keylog.Load(path));
  EXPECT_EQ(keylog.SecretCount(), 1u);
  EXPECT_EQ(keylog.SessionCount(), 1u);

  {
    std::ofstream out(path, std::ios::app);
    out << "CLIENT_TRAFFIC_SECRET_0 " << MakeRandomHex() << " " << std::string(64, '2') << "\n";
  }
  ASSERT_TRUE(keylog.Refresh());
  EXPECT_EQ(keylog.SecretCount(), 2u);

  auto secrets = keylog.Lookup(MakeRandomHex());
  ASSERT_TRUE(secrets);
  EXPECT_EQ(secrets->master_secret.size(), 48u);
  EXPECT_EQ(secrets->client_traffic_secret_0.size(), 32u);

  // Truncate and rewrite.
  {
    std::ofstream out(path, std::ios::trunc);
    out << "SERVER_TRAFFIC_SECRET_0 " << MakeRandomHex() << " " << std::string(64, '3') << "\n";
  }
  ASSERT_TRUE(keylog.Refresh());
  auto again = keylog.Lookup(MakeRandomHex());
  ASSERT_TRUE(again);
  EXPECT_EQ(again->server_traffic_secret_0.size(), 32u);

  std::remove(path.c_str());
}

TEST(TlsCipherTest, MapsKnownSuites) {
  auto aes = LookupCipherSuite(0x1301);
  ASSERT_TRUE(aes);
  EXPECT_EQ(aes->key_len, 16u);
  EXPECT_TRUE(aes->tls13_only);

  auto gcm12 = LookupCipherSuite(0xC02F);
  ASSERT_TRUE(gcm12);
  EXPECT_TRUE(gcm12->tls12_only);
  EXPECT_FALSE(LookupCipherSuite(0x0000).has_value());
}

#if defined(WIREPEEK_ENABLE_TLS_DECRYPT)

TEST(TlsCryptoTest, Tls13HkdfExpandLabelKnownAnswer) {
  // Derived from OpenSSL TLS13-KDF expand-only fixture (key/label/context/output).
  std::vector<uint8_t> secret = {0xbc, 0x7c, 0xe3, 0x02, 0x7c, 0xd6, 0x7b, 0xbf, 0x36, 0x6c, 0x78,
                                 0xe0, 0x70, 0x23, 0xf2, 0xef, 0xed, 0xab, 0x1e, 0x02, 0x13, 0x66,
                                 0xa3, 0xbd, 0xf7, 0xe8, 0xf0, 0x33, 0x1d, 0xe1, 0x11, 0x3c};
  std::vector<uint8_t> context = {0x6a, 0x59, 0x3b, 0xa3, 0x9e, 0x4e, 0xa7, 0x23, 0x92, 0xa7, 0xfc,
                                  0x41, 0x98, 0xd5, 0x6c, 0x01, 0xdd, 0x25, 0x09, 0x4c, 0x80, 0x8f,
                                  0x9d, 0xc8, 0xf7, 0xed, 0x39, 0xe8, 0x08, 0xdd, 0x1e, 0x58};
  // label bytes in OpenSSL fixture are "c hs traffic" without "tls13 " prefix.
  auto out = Tls13HkdfExpandLabel(TlsHash::kSha256, secret, "c hs traffic", context, 32);
  ASSERT_TRUE(out);
  ASSERT_EQ(out->size(), 32u);
  const std::vector<uint8_t> expected = {0x3c, 0x80, 0x83, 0x86, 0xd1, 0x73, 0xaa, 0x3e,
                                         0xda, 0xd8, 0xe0, 0xeb, 0x9e, 0x9b, 0xbe, 0xc6,
                                         0x29, 0xd5, 0xa0, 0x0d, 0x35, 0x03, 0xf1, 0xa5,
                                         0x24, 0xaa, 0x75, 0xc7, 0xe8, 0xff, 0x40, 0x02};
  EXPECT_EQ(*out, expected);
}

TEST(TlsCryptoTest, AeadRoundTripAndBadTagFailClosed) {
  auto suite = LookupCipherSuite(0x1301);
  ASSERT_TRUE(suite);

  std::vector<uint8_t> key(16, 0x11);
  std::vector<uint8_t> iv(12, 0x22);
  std::vector<uint8_t> aad = {0x17, 0x03, 0x03, 0x00, 0x15};
  std::vector<uint8_t> plaintext = {'h', 'e', 'l', 'l', 'o'};

  EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, "AES-128-GCM", nullptr);
  ASSERT_NE(cipher, nullptr);
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  ASSERT_NE(ctx, nullptr);
  ASSERT_EQ(EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr), 1);
  ASSERT_EQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr), 1);
  ASSERT_EQ(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()), 1);
  int len = 0;
  ASSERT_EQ(EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())), 1);
  std::vector<uint8_t> ciphertext(plaintext.size());
  ASSERT_EQ(EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(),
                              static_cast<int>(plaintext.size())),
            1);
  int final_len = 0;
  ASSERT_EQ(EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &final_len), 1);
  std::vector<uint8_t> tag(16);
  ASSERT_EQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag.data()), 1);
  EVP_CIPHER_CTX_free(ctx);
  EVP_CIPHER_free(cipher);

  std::vector<uint8_t> ct_and_tag = ciphertext;
  ct_and_tag.insert(ct_and_tag.end(), tag.begin(), tag.end());

  auto ok = AeadDecrypt(*suite, key, iv, aad, ct_and_tag);
  EXPECT_EQ(ok.status, TlsDecryptStatus::kOk);
  EXPECT_EQ(ok.plaintext, plaintext);

  ct_and_tag.back() ^= 0xFF;
  auto bad = AeadDecrypt(*suite, key, iv, aad, ct_and_tag);
  EXPECT_EQ(bad.status, TlsDecryptStatus::kAuthFailed);
  EXPECT_TRUE(bad.plaintext.empty());
}

TEST(TlsCryptoTest, Tls13TrafficKeyDerivation) {
  auto suite = LookupCipherSuite(0x1301);
  ASSERT_TRUE(suite);
  std::vector<uint8_t> secret(32, 0xAB);
  auto keys = Tls13DeriveTrafficKeys(*suite, secret);
  ASSERT_TRUE(keys);
  EXPECT_EQ(keys->key.size(), 16u);
  EXPECT_EQ(keys->iv.size(), 12u);
}

#else

TEST(TlsCryptoTest, UnavailableWithoutOpenSsl) {
  EXPECT_FALSE(TlsCryptoAvailable());
  auto suite = LookupCipherSuite(0x1301);
  ASSERT_TRUE(suite);
  auto result = AeadDecrypt(*suite, std::vector<uint8_t>(16), std::vector<uint8_t>(12), {},
                            std::vector<uint8_t>(32));
  EXPECT_EQ(result.status, TlsDecryptStatus::kCryptoUnavailable);
}

#endif

}  // namespace
}  // namespace wirepeek::protocol
