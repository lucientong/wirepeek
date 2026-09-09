// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/tls_crypto.h>

#include <algorithm>
#include <array>
#include <cstring>

#if defined(WIREPEEK_ENABLE_TLS_DECRYPT)
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#endif

namespace wirepeek::protocol {
namespace {

void SecureClear(std::vector<uint8_t>& bytes) {
  if (!bytes.empty()) {
    std::fill(bytes.begin(), bytes.end(), static_cast<uint8_t>(0));
    bytes.clear();
  }
}

#if defined(WIREPEEK_ENABLE_TLS_DECRYPT)

const char* DigestName(TlsHash hash) {
  return hash == TlsHash::kSha384 ? "SHA384" : "SHA256";
}

std::optional<std::vector<uint8_t>> EvpKdfDerive(const char* kdf_name,
                                                 const OSSL_PARAM* params, size_t out_len) {
  EVP_KDF* kdf = EVP_KDF_fetch(nullptr, kdf_name, nullptr);
  if (!kdf)
    return std::nullopt;
  EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);
  if (!ctx)
    return std::nullopt;

  std::vector<uint8_t> out(out_len);
  const int ok = EVP_KDF_derive(ctx, out.data(), out.size(), params);
  EVP_KDF_CTX_free(ctx);
  if (ok <= 0) {
    SecureClear(out);
    return std::nullopt;
  }
  return out;
}

#endif

}  // namespace

bool TlsCryptoAvailable() {
#if defined(WIREPEEK_ENABLE_TLS_DECRYPT)
  return true;
#else
  return false;
#endif
}

std::optional<std::vector<uint8_t>> Tls13HkdfExpandLabel(TlsHash hash,
                                                         std::span<const uint8_t> secret,
                                                         std::string_view label,
                                                         std::span<const uint8_t> context,
                                                         size_t length) {
#if !defined(WIREPEEK_ENABLE_TLS_DECRYPT)
  (void)hash;
  (void)secret;
  (void)label;
  (void)context;
  (void)length;
  return std::nullopt;
#else
  // HkdfLabel = uint16 length || uint8 label_len || "tls13 " + label || uint8 context_len || context
  const std::string full_label = std::string("tls13 ") + std::string(label);
  std::vector<uint8_t> hkdf_label;
  hkdf_label.reserve(2 + 1 + full_label.size() + 1 + context.size());
  hkdf_label.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
  hkdf_label.push_back(static_cast<uint8_t>(length & 0xFF));
  hkdf_label.push_back(static_cast<uint8_t>(full_label.size()));
  hkdf_label.insert(hkdf_label.end(), full_label.begin(), full_label.end());
  hkdf_label.push_back(static_cast<uint8_t>(context.size()));
  hkdf_label.insert(hkdf_label.end(), context.begin(), context.end());

  int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
      OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(DigestName(hash)),
                                      0),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(secret.data()),
                                        secret.size()),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, hkdf_label.data(), hkdf_label.size()),
      OSSL_PARAM_construct_end(),
  };
  auto out = EvpKdfDerive("HKDF", params, length);
  SecureClear(hkdf_label);
  return out;
#endif
}

std::optional<TlsTrafficKeys> Tls13DeriveTrafficKeys(const TlsCipherSuiteInfo& suite,
                                                     std::span<const uint8_t> traffic_secret) {
  auto key = Tls13HkdfExpandLabel(suite.hash, traffic_secret, "key", {}, suite.key_len);
  auto iv = Tls13HkdfExpandLabel(suite.hash, traffic_secret, "iv", {}, suite.iv_len);
  if (!key || !iv)
    return std::nullopt;
  return TlsTrafficKeys{std::move(*key), std::move(*iv)};
}

std::optional<std::vector<uint8_t>> Tls13UpdateTrafficSecret(
    const TlsCipherSuiteInfo& suite, std::span<const uint8_t> traffic_secret) {
  return Tls13HkdfExpandLabel(suite.hash, traffic_secret, "traffic upd", {}, suite.hash_len);
}

std::optional<std::vector<uint8_t>> Tls12PrfKeyBlock(
    const TlsCipherSuiteInfo& suite, std::span<const uint8_t> master_secret,
    std::span<const uint8_t, 32> client_random, std::span<const uint8_t, 32> server_random,
    size_t length) {
#if !defined(WIREPEEK_ENABLE_TLS_DECRYPT)
  (void)suite;
  (void)master_secret;
  (void)client_random;
  (void)server_random;
  (void)length;
  return std::nullopt;
#else
  // seed = client_random || server_random for "key expansion"
  std::array<uint8_t, 64> seed{};
  std::copy(server_random.begin(), server_random.end(), seed.begin());
  std::copy(client_random.begin(), client_random.end(), seed.begin() + 32);

  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(suite.openssl_digest),
                                      0),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET,
                                        const_cast<uint8_t*>(master_secret.data()),
                                        master_secret.size()),
      OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SEED, const_cast<char*>("key expansion"), 0),
      // OpenSSL TLS1-PRF expects seed parts via repeated SEED params; also accept DATA.
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, seed.data(), seed.size()),
      OSSL_PARAM_construct_end(),
  };
  // Prefer dedicated TLS1-PRF; fall back to constructing seed manually if needed.
  auto out = EvpKdfDerive("TLS1-PRF", params, length);
  if (out)
    return out;

  // Some OpenSSL builds want label separate and seed as client||server order for key expansion:
  // Actually RFC 5246: key_block = PRF(master, "key expansion", server_random + client_random)
  std::array<uint8_t, 64> seed2{};
  std::copy(server_random.begin(), server_random.end(), seed2.begin());
  std::copy(client_random.begin(), client_random.end(), seed2.begin() + 32);
  char label[] = "key expansion";
  OSSL_PARAM params2[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(suite.openssl_digest),
                                      0),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET,
                                        const_cast<uint8_t*>(master_secret.data()),
                                        master_secret.size()),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, label, sizeof(label) - 1),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, seed2.data(), seed2.size()),
      OSSL_PARAM_construct_end(),
  };
  return EvpKdfDerive("TLS1-PRF", params2, length);
#endif
}

std::optional<Tls12DirectionKeys> Tls12DeriveKeys(
    const TlsCipherSuiteInfo& suite, std::span<const uint8_t> master_secret,
    std::span<const uint8_t, 32> client_random, std::span<const uint8_t, 32> server_random) {
  // key_block = client_write_key || server_write_key || client_write_IV || server_write_IV
  // (MAC keys omitted for AEAD)
  const size_t needed = suite.key_len * 2 + suite.iv_len * 2;
  auto block = Tls12PrfKeyBlock(suite, master_secret, client_random, server_random, needed);
  if (!block || block->size() < needed)
    return std::nullopt;

  Tls12DirectionKeys keys;
  size_t off = 0;
  keys.client_write_key.assign(block->begin() + static_cast<std::ptrdiff_t>(off),
                               block->begin() + static_cast<std::ptrdiff_t>(off + suite.key_len));
  off += suite.key_len;
  keys.server_write_key.assign(block->begin() + static_cast<std::ptrdiff_t>(off),
                               block->begin() + static_cast<std::ptrdiff_t>(off + suite.key_len));
  off += suite.key_len;
  keys.client_write_iv.assign(block->begin() + static_cast<std::ptrdiff_t>(off),
                              block->begin() + static_cast<std::ptrdiff_t>(off + suite.iv_len));
  off += suite.iv_len;
  keys.server_write_iv.assign(block->begin() + static_cast<std::ptrdiff_t>(off),
                              block->begin() + static_cast<std::ptrdiff_t>(off + suite.iv_len));
  SecureClear(*block);
  return keys;
}

TlsDecryptResult AeadDecrypt(const TlsCipherSuiteInfo& suite, std::span<const uint8_t> key,
                             std::span<const uint8_t> nonce, std::span<const uint8_t> aad,
                             std::span<const uint8_t> ciphertext_and_tag) {
  TlsDecryptResult result;
#if !defined(WIREPEEK_ENABLE_TLS_DECRYPT)
  (void)suite;
  (void)key;
  (void)nonce;
  (void)aad;
  (void)ciphertext_and_tag;
  result.status = TlsDecryptStatus::kCryptoUnavailable;
  return result;
#else
  if (key.size() != suite.key_len || ciphertext_and_tag.size() < suite.tag_len) {
    result.status = TlsDecryptStatus::kInvalidInput;
    return result;
  }
  const size_t ct_len = ciphertext_and_tag.size() - suite.tag_len;
  const auto* ciphertext = ciphertext_and_tag.data();
  const auto* tag = ciphertext_and_tag.data() + ct_len;

  EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, suite.openssl_cipher, nullptr);
  if (!cipher) {
    result.status = TlsDecryptStatus::kUnsupported;
    return result;
  }
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    EVP_CIPHER_free(cipher);
    result.status = TlsDecryptStatus::kUnsupported;
    return result;
  }

  auto fail = [&](TlsDecryptStatus status) {
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    SecureClear(result.plaintext);
    result.plaintext.clear();
    result.status = status;
    return result;
  };

  if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1)
    return fail(TlsDecryptStatus::kUnsupported);
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) !=
      1)
    return fail(TlsDecryptStatus::kInvalidInput);
  if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
    return fail(TlsDecryptStatus::kInvalidInput);

  int len = 0;
  if (!aad.empty()) {
    if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
      return fail(TlsDecryptStatus::kAuthFailed);
  }

  result.plaintext.resize(ct_len);
  if (ct_len > 0) {
    if (EVP_DecryptUpdate(ctx, result.plaintext.data(), &len, ciphertext, static_cast<int>(ct_len)) !=
        1)
      return fail(TlsDecryptStatus::kAuthFailed);
  } else {
    len = 0;
  }
  int plaintext_len = len;

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(suite.tag_len),
                          const_cast<uint8_t*>(tag)) != 1)
    return fail(TlsDecryptStatus::kAuthFailed);

  int final_len = 0;
  if (EVP_DecryptFinal_ex(ctx, result.plaintext.data() + plaintext_len, &final_len) != 1)
    return fail(TlsDecryptStatus::kAuthFailed);

  plaintext_len += final_len;
  result.plaintext.resize(static_cast<size_t>(plaintext_len));
  EVP_CIPHER_CTX_free(ctx);
  EVP_CIPHER_free(cipher);
  result.status = TlsDecryptStatus::kOk;
  return result;
#endif
}

}  // namespace wirepeek::protocol
