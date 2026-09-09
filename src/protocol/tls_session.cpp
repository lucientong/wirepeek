// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/tls.h>
#include <wirepeek/protocol/tls_session.h>

#include <spdlog/spdlog.h>

namespace wirepeek::protocol {
namespace {

size_t DirIndex(StreamDirection direction) {
  return direction == StreamDirection::kClientToServer ? 0 : 1;
}

TlsDirection ToTlsDir(StreamDirection direction) {
  return direction == StreamDirection::kClientToServer ? TlsDirection::kClient
                                                       : TlsDirection::kServer;
}

StreamDirection FromTlsDir(TlsDirection dir) {
  return dir == TlsDirection::kClient ? StreamDirection::kClientToServer
                                      : StreamDirection::kServerToClient;
}

}  // namespace

TlsSession::TlsSession(std::shared_ptr<TlsKeyLog> keylog) : keylog_(std::move(keylog)) {}

std::optional<std::chrono::microseconds> TlsSession::HandshakeDuration() const {
  if (!client_hello_ts_ || !handshake_complete_ts_)
    return std::nullopt;
  if (*handshake_complete_ts_ < *client_hello_ts_)
    return std::nullopt;
  return std::chrono::duration_cast<std::chrono::microseconds>(*handshake_complete_ts_ -
                                                               *client_hello_ts_);
}

void TlsSession::TryInitDecryptor() {
  if (decrypt_attempted_ || !client_hello_ || !server_hello_ || !keylog_)
    return;
  decrypt_attempted_ = true;
  if (!TlsCryptoAvailable()) {
    if (!status_emitted_) {
      status_emitted_ = true;
      spdlog::warn("TLS keylog provided but OpenSSL decryption is disabled at build time");
    }
    return;
  }
  const auto random_hex = HexEncode(client_hello_->client_random);
  auto secrets = keylog_->Lookup(random_hex);
  if (!secrets) {
    if (!status_emitted_) {
      status_emitted_ = true;
      spdlog::debug("No TLS keylog secrets for client_random {}", random_hex);
    }
    return;
  }
  if (!decryptor_.InitializeFromHandshake(*client_hello_, *server_hello_, *secrets)) {
    if (!status_emitted_) {
      status_emitted_ = true;
      spdlog::debug("TLS decrypt init failed (unsupported suite or missing secrets)");
    }
  }
}

void TlsSession::HandlePlainHandshake(TlsDirection dir, std::span<const uint8_t> payload,
                                      Timestamp ts, TlsSessionResult& out) {
  const size_t idx = dir == TlsDirection::kClient ? 0 : 1;
  auto messages = handshake_reassemblers_[idx].Feed(payload);
  for (auto& msg : messages) {
    if (msg.type == TlsHandshakeType::kClientHello) {
      auto info = ParseTlsClientHelloBody(msg.body);
      if (info) {
        info->timestamp = ts;
        client_hello_ = *info;
        client_hello_ts_ = ts;
        if (!info->alpn.empty())
          alpn_ = info->alpn.front();
        out.handshakes.push_back(*info);
        TryInitDecryptor();
      }
    } else if (msg.type == TlsHandshakeType::kServerHello) {
      auto info = ParseTlsServerHelloBody(msg.body);
      if (info) {
        info->timestamp = ts;
        if (client_hello_) {
          info->client_random = client_hello_->client_random;
          info->has_client_random = client_hello_->has_client_random;
          if (info->alpn.empty())
            info->alpn = client_hello_->alpn;
          if (info->sni.empty())
            info->sni = client_hello_->sni;
        }
        if (!info->alpn.empty())
          alpn_ = info->alpn.front();
        else if (client_hello_ && !client_hello_->alpn.empty())
          alpn_ = client_hello_->alpn.front();
        server_hello_ = *info;
        out.handshakes.push_back(*info);
        TryInitDecryptor();
      }
    } else if (msg.type == TlsHandshakeType::kFinished) {
      handshake_complete_ts_ = ts;
    } else if (msg.type == TlsHandshakeType::kKeyUpdate) {
      decryptor_.OnKeyUpdate(dir, msg.body);
    }
  }
}

void TlsSession::HandlePlaintext(TlsDirection dir, const TlsPlaintextRecord& plain, Timestamp ts,
                                 TlsSessionResult& out) {
  if (plain.type == TlsContentType::kHandshake) {
    HandlePlainHandshake(dir, plain.data, ts, out);
    return;
  }
  if (plain.type == TlsContentType::kApplicationData && !plain.data.empty()) {
    if (!handshake_complete_ts_)
      handshake_complete_ts_ = ts;
    out.application.push_back(TlsApplicationBytes{
        .direction = FromTlsDir(dir),
        .data = plain.data,
        .timestamp = ts,
    });
  }
}

TlsSessionResult TlsSession::Feed(std::span<const uint8_t> data, StreamDirection direction,
                                  Timestamp ts) {
  TlsSessionResult out;
  const size_t idx = DirIndex(direction);
  const auto tls_dir = ToTlsDir(direction);
  if (framers_[idx].Failed()) {
    if (!status_emitted_) {
      status_emitted_ = true;
      out.status = "tls_record_framing_failed";
    }
    return out;
  }

  auto records = framers_[idx].Feed(data);
  for (auto& record : records) {
    switch (record.type) {
      case TlsContentType::kChangeCipherSpec:
        decryptor_.OnChangeCipherSpec(tls_dir);
        break;
      case TlsContentType::kAlert:
        break;
      case TlsContentType::kHandshake:
        HandlePlainHandshake(tls_dir, record.payload, ts, out);
        break;
      case TlsContentType::kApplicationData: {
        // Refresh keylog lazily in case secrets arrived after ClientHello.
        if (keylog_ && client_hello_ && !decryptor_.Ready()) {
          decrypt_attempted_ = false;
          TryInitDecryptor();
        }
        auto plain = decryptor_.DecryptRecord(tls_dir, record);
        if (plain) {
          HandlePlaintext(tls_dir, *plain, ts, out);
        } else if (decryptor_.DirectionAbandoned(tls_dir) && !status_emitted_) {
          status_emitted_ = true;
          out.status = "tls_decrypt_abandoned";
        }
        break;
      }
    }
  }

  if (framers_[idx].Failed() && !status_emitted_) {
    status_emitted_ = true;
    out.status = "tls_record_framing_failed";
  }
  return out;
}

}  // namespace wirepeek::protocol
