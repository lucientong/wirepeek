// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/endian.h>
#include <wirepeek/protocol/tls_decryptor.h>

#include <algorithm>

namespace wirepeek::protocol {
namespace {

void SecureClear(std::vector<uint8_t>& bytes) {
  if (!bytes.empty()) {
    std::fill(bytes.begin(), bytes.end(), static_cast<uint8_t>(0));
    bytes.clear();
  }
}

std::vector<uint8_t> MakeTls12Aad(TlsContentType type, uint16_t version, uint64_t seq,
                                  uint16_t length) {
  std::vector<uint8_t> aad(13);
  for (int i = 7; i >= 0; --i)
    aad[static_cast<size_t>(7 - i)] = static_cast<uint8_t>((seq >> (i * 8)) & 0xFF);
  aad[8] = static_cast<uint8_t>(type);
  aad[9] = static_cast<uint8_t>((version >> 8) & 0xFF);
  aad[10] = static_cast<uint8_t>(version & 0xFF);
  aad[11] = static_cast<uint8_t>((length >> 8) & 0xFF);
  aad[12] = static_cast<uint8_t>(length & 0xFF);
  return aad;
}

std::vector<uint8_t> MakeTls13Aad(TlsContentType type, uint16_t version, uint16_t length) {
  std::vector<uint8_t> aad(5);
  aad[0] = static_cast<uint8_t>(type);
  aad[1] = static_cast<uint8_t>((version >> 8) & 0xFF);
  aad[2] = static_cast<uint8_t>(version & 0xFF);
  aad[3] = static_cast<uint8_t>((length >> 8) & 0xFF);
  aad[4] = static_cast<uint8_t>(length & 0xFF);
  return aad;
}

bool ContainsFinished(std::span<const uint8_t> handshake_bytes) {
  size_t pos = 0;
  while (pos + 4 <= handshake_bytes.size()) {
    const uint8_t type = handshake_bytes[pos];
    const uint32_t len = (static_cast<uint32_t>(handshake_bytes[pos + 1]) << 16) |
                         (static_cast<uint32_t>(handshake_bytes[pos + 2]) << 8) |
                         static_cast<uint32_t>(handshake_bytes[pos + 3]);
    if (type == static_cast<uint8_t>(TlsHandshakeType::kFinished))
      return true;
    pos += 4 + static_cast<size_t>(len);
    if (len > handshake_bytes.size())
      break;
  }
  return false;
}

}  // namespace

void TlsDirectionDecryptor::Abandon() {
  abandoned_ = true;
  ready_ = false;
  SecureClear(traffic_secret_);
  SecureClear(key_);
  SecureClear(iv_);
}

void TlsDirectionDecryptor::ConfigureTls13(const TlsCipherSuiteInfo& suite,
                                           std::vector<uint8_t> traffic_secret) {
  suite_ = suite;
  tls13_ = true;
  traffic_secret_ = std::move(traffic_secret);
  auto keys = Tls13DeriveTrafficKeys(suite_, traffic_secret_);
  if (!keys) {
    Abandon();
    return;
  }
  key_ = std::move(keys->key);
  iv_ = std::move(keys->iv);
  sequence_ = 0;
  consecutive_failures_ = 0;
  abandoned_ = false;
  ready_ = true;
}

void TlsDirectionDecryptor::ConfigureTls12(const TlsCipherSuiteInfo& suite,
                                           std::vector<uint8_t> write_key,
                                           std::vector<uint8_t> write_iv) {
  suite_ = suite;
  tls13_ = false;
  key_ = std::move(write_key);
  iv_ = std::move(write_iv);
  sequence_ = 0;
  consecutive_failures_ = 0;
  abandoned_ = false;
  ready_ = true;
}

bool TlsDirectionDecryptor::UpdateTrafficSecret() {
  if (!ready_ || !tls13_ || abandoned_)
    return false;
  auto next = Tls13UpdateTrafficSecret(suite_, traffic_secret_);
  if (!next)
    return false;
  SecureClear(traffic_secret_);
  traffic_secret_ = std::move(*next);
  auto keys = Tls13DeriveTrafficKeys(suite_, traffic_secret_);
  if (!keys) {
    Abandon();
    return false;
  }
  SecureClear(key_);
  SecureClear(iv_);
  key_ = std::move(keys->key);
  iv_ = std::move(keys->iv);
  sequence_ = 0;
  return true;
}

std::array<uint8_t, 12> TlsDirectionDecryptor::BuildNonce(
    std::span<const uint8_t> explicit_nonce) const {
  std::array<uint8_t, 12> nonce{};
  if (tls13_ || suite_.aead == TlsAeadCipher::kChaCha20Poly1305) {
    std::copy_n(iv_.begin(), std::min<size_t>(iv_.size(), 12), nonce.begin());
    for (int i = 0; i < 8; ++i)
      nonce[static_cast<size_t>(11 - i)] ^= static_cast<uint8_t>((sequence_ >> (i * 8)) & 0xFF);
  } else {
    std::copy_n(iv_.begin(), std::min<size_t>(iv_.size(), 4), nonce.begin());
    if (explicit_nonce.size() >= 8)
      std::copy_n(explicit_nonce.begin(), 8, nonce.begin() + 4);
  }
  return nonce;
}

std::optional<TlsPlaintextRecord> TlsDirectionDecryptor::Decrypt(const TlsRecord& record) {
  if (abandoned_ || !ready_)
    return std::nullopt;

  // Encrypted TLS records always use outer type ApplicationData (TLS 1.3) or ApplicationData
  // after CCS (TLS 1.2). Handshake/CCS/alert plaintext are handled elsewhere.
  if (record.type != TlsContentType::kApplicationData)
    return std::nullopt;

  std::span<const uint8_t> payload = record.payload;
  std::span<const uint8_t> explicit_nonce;
  std::vector<uint8_t> aad;
  std::span<const uint8_t> ciphertext;

  if (tls13_) {
    aad = MakeTls13Aad(record.type, record.version, static_cast<uint16_t>(record.payload.size()));
    ciphertext = payload;
  } else if (suite_.aead == TlsAeadCipher::kChaCha20Poly1305) {
    if (payload.size() < suite_.tag_len)
      return std::nullopt;
    aad = MakeTls12Aad(record.type, record.version, sequence_,
                       static_cast<uint16_t>(payload.size() - suite_.tag_len));
    ciphertext = payload;
  } else {
    if (payload.size() < 8 + suite_.tag_len)
      return std::nullopt;
    explicit_nonce = payload.subspan(0, 8);
    ciphertext = payload.subspan(8);
    aad = MakeTls12Aad(record.type, record.version, sequence_,
                       static_cast<uint16_t>(ciphertext.size() - suite_.tag_len));
  }

  const auto nonce = BuildNonce(explicit_nonce);
  auto decrypted = AeadDecrypt(suite_, key_, nonce, aad, ciphertext);
  if (decrypted.status != TlsDecryptStatus::kOk) {
    ++consecutive_failures_;
    if (consecutive_failures_ >= kMaxFailures)
      Abandon();
    return std::nullopt;
  }

  consecutive_failures_ = 0;
  ++sequence_;

  TlsPlaintextRecord plain;
  if (tls13_) {
    auto& bytes = decrypted.plaintext;
    while (!bytes.empty() && bytes.back() == 0)
      bytes.pop_back();
    if (bytes.empty())
      return std::nullopt;
    plain.type = static_cast<TlsContentType>(bytes.back());
    bytes.pop_back();
    plain.data = std::move(bytes);
  } else {
    plain.type = TlsContentType::kApplicationData;
    plain.data = std::move(decrypted.plaintext);
  }
  return plain;
}

bool TlsDecryptor::InitializeFromHandshake(const TlsHandshakeInfo& client_hello,
                                           const TlsHandshakeInfo& server_hello,
                                           const TlsKeyLogSecrets& secrets) {
  auto suite = LookupCipherSuite(server_hello.cipher_suite_id);
  if (!suite)
    return false;
  suite_ = *suite;
  tls13_ = server_hello.version == 0x0304 || suite_.tls13_only;
  if (tls13_ && suite_.tls12_only)
    return false;
  if (!tls13_ && suite_.tls13_only)
    return false;

  if (tls13_) {
    have_app_secrets_ =
        !secrets.client_traffic_secret_0.empty() && !secrets.server_traffic_secret_0.empty();
    const bool have_hs = !secrets.client_handshake_traffic_secret.empty() &&
                         !secrets.server_handshake_traffic_secret.empty();
    if (!have_hs && !have_app_secrets_)
      return false;
    if (have_hs) {
      client_hs_.ConfigureTls13(suite_, secrets.client_handshake_traffic_secret);
      server_hs_.ConfigureTls13(suite_, secrets.server_handshake_traffic_secret);
    }
    if (have_app_secrets_) {
      client_app_.ConfigureTls13(suite_, secrets.client_traffic_secret_0);
      server_app_.ConfigureTls13(suite_, secrets.server_traffic_secret_0);
      // If handshake secrets are missing, jump straight to application epoch.
      if (!have_hs) {
        client_app_active_ = true;
        server_app_active_ = true;
      }
    }
    ready_ = true;
    return true;
  }

  if (secrets.master_secret.empty() || !client_hello.has_client_random ||
      !server_hello.has_server_random)
    return false;
  auto keys = Tls12DeriveKeys(suite_, secrets.master_secret, client_hello.client_random,
                              server_hello.server_random);
  if (!keys)
    return false;
  client_app_.ConfigureTls12(suite_, std::move(keys->client_write_key),
                             std::move(keys->client_write_iv));
  server_app_.ConfigureTls12(suite_, std::move(keys->server_write_key),
                             std::move(keys->server_write_iv));
  client_app_active_ = true;
  server_app_active_ = true;
  ready_ = client_app_.Ready() && server_app_.Ready();
  return ready_;
}

void TlsDecryptor::OnChangeCipherSpec(TlsDirection dir) {
  if (tls13_)
    return;
  if (dir == TlsDirection::kClient)
    client_ccs_ = true;
  else
    server_ccs_ = true;
}

bool TlsDecryptor::OnKeyUpdate(TlsDirection dir, std::span<const uint8_t> body) {
  (void)body;
  if (!tls13_)
    return false;
  auto& dec = dir == TlsDirection::kClient ? client_app_ : server_app_;
  if (dir == TlsDirection::kClient)
    client_app_active_ = true;
  else
    server_app_active_ = true;
  return dec.UpdateTrafficSecret();
}

void TlsDecryptor::MaybePromoteToApplication(TlsDirection dir, const TlsPlaintextRecord& plain) {
  if (!tls13_ || !have_app_secrets_)
    return;
  if (plain.type != TlsContentType::kHandshake)
    return;
  if (!ContainsFinished(plain.data))
    return;
  if (dir == TlsDirection::kClient)
    client_app_active_ = true;
  else
    server_app_active_ = true;
}

std::optional<TlsPlaintextRecord> TlsDecryptor::DecryptRecord(TlsDirection dir,
                                                              const TlsRecord& record) {
  if (!ready_)
    return std::nullopt;

  if (!tls13_) {
    const bool ccs = dir == TlsDirection::kClient ? client_ccs_ : server_ccs_;
    if (!ccs)
      return std::nullopt;
    auto& dec = dir == TlsDirection::kClient ? client_app_ : server_app_;
    return dec.Decrypt(record);
  }

  const bool app_active = dir == TlsDirection::kClient ? client_app_active_ : server_app_active_;
  auto& hs = dir == TlsDirection::kClient ? client_hs_ : server_hs_;
  auto& app = dir == TlsDirection::kClient ? client_app_ : server_app_;

  if (app_active && app.Ready()) {
    auto plain = app.Decrypt(record);
    if (plain)
      return plain;
    // Fall through to handshake epoch only if app decrypt failed early in the connection.
  }

  if (!app_active && hs.Ready()) {
    auto plain = hs.Decrypt(record);
    if (plain) {
      MaybePromoteToApplication(dir, *plain);
      return plain;
    }
  }

  // Last resort: try the other epoch once (handles missing Finished observation).
  if (!app_active && app.Ready()) {
    auto plain = app.Decrypt(record);
    if (plain) {
      if (dir == TlsDirection::kClient)
        client_app_active_ = true;
      else
        server_app_active_ = true;
      return plain;
    }
  }
  return std::nullopt;
}

bool TlsDecryptor::DirectionAbandoned(TlsDirection dir) const {
  if (tls13_) {
    const bool app = dir == TlsDirection::kClient ? client_app_active_ : server_app_active_;
    if (app)
      return dir == TlsDirection::kClient ? client_app_.Abandoned() : server_app_.Abandoned();
    return dir == TlsDirection::kClient ? client_hs_.Abandoned() : server_hs_.Abandoned();
  }
  return dir == TlsDirection::kClient ? client_app_.Abandoned() : server_app_.Abandoned();
}

}  // namespace wirepeek::protocol
