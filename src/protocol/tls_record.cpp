// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/endian.h>
#include <wirepeek/protocol/tls_record.h>

namespace wirepeek::protocol {

void TlsRecordFramer::Reset() {
  buffer_.clear();
  failed_ = false;
}

std::vector<TlsRecord> TlsRecordFramer::Feed(std::span<const uint8_t> data) {
  std::vector<TlsRecord> out;
  if (failed_ || data.empty())
    return out;

  if (buffer_.size() + data.size() > kMaxBuffer) {
    failed_ = true;
    buffer_.clear();
    return out;
  }
  buffer_.insert(buffer_.end(), data.begin(), data.end());

  while (buffer_.size() >= kHeaderLen) {
    const uint8_t type = buffer_[0];
    if (type < 20 || type > 23) {
      failed_ = true;
      buffer_.clear();
      return out;
    }
    const uint16_t version = ReadU16Be(buffer_.data() + 1);
    const uint16_t length = ReadU16Be(buffer_.data() + 3);
    if (length > kMaxRecordPayload) {
      failed_ = true;
      buffer_.clear();
      return out;
    }
    const size_t total = kHeaderLen + static_cast<size_t>(length);
    if (buffer_.size() < total)
      break;

    TlsRecord record;
    record.type = static_cast<TlsContentType>(type);
    record.version = version;
    record.payload.assign(buffer_.begin() + static_cast<std::ptrdiff_t>(kHeaderLen),
                          buffer_.begin() + static_cast<std::ptrdiff_t>(total));
    out.push_back(std::move(record));
    buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(total));
  }
  return out;
}

void TlsHandshakeReassembler::Reset() {
  buffer_.clear();
  failed_ = false;
}

std::vector<TlsHandshakeMessage> TlsHandshakeReassembler::Feed(
    std::span<const uint8_t> handshake_payload) {
  std::vector<TlsHandshakeMessage> out;
  if (failed_ || handshake_payload.empty())
    return out;

  if (buffer_.size() + handshake_payload.size() > kMaxMessage * 4) {
    failed_ = true;
    buffer_.clear();
    return out;
  }
  buffer_.insert(buffer_.end(), handshake_payload.begin(), handshake_payload.end());

  while (buffer_.size() >= 4) {
    const uint8_t type = buffer_[0];
    const uint32_t length = (static_cast<uint32_t>(buffer_[1]) << 16) |
                            (static_cast<uint32_t>(buffer_[2]) << 8) |
                            static_cast<uint32_t>(buffer_[3]);
    if (length > kMaxMessage) {
      failed_ = true;
      buffer_.clear();
      return out;
    }
    const size_t total = 4 + static_cast<size_t>(length);
    if (buffer_.size() < total)
      break;

    TlsHandshakeMessage msg;
    msg.type = static_cast<TlsHandshakeType>(type);
    msg.body.assign(buffer_.begin() + 4, buffer_.begin() + static_cast<std::ptrdiff_t>(total));
    out.push_back(std::move(msg));
    buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(total));
  }
  return out;
}

}  // namespace wirepeek::protocol
