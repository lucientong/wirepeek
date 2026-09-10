// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/endian.h>
#include <wirepeek/protocol/tls.h>

#include <algorithm>
#include <cctype>
#include <fmt/format.h>

namespace wirepeek::protocol {

namespace {

// TLS record header: ContentType(1) + Version(2) + Length(2) = 5 bytes.
// Handshake header: HandshakeType(1) + Length(3) = 4 bytes.
constexpr size_t kTlsRecordHeaderLen = 5;
constexpr size_t kHandshakeHeaderLen = 4;

constexpr uint16_t kExtSNI = 0x0000;
constexpr uint16_t kExtALPN = 0x0010;
constexpr uint16_t kExtSupportedVersions = 0x002B;

std::optional<std::span<const uint8_t>> HandshakeBodyFromRecord(std::span<const uint8_t> data,
                                                                uint8_t expected_type) {
  if (data.size() < kTlsRecordHeaderLen + kHandshakeHeaderLen)
    return std::nullopt;
  if (data[0] != 0x16)
    return std::nullopt;
  const uint16_t record_len = ReadU16Be(data.data() + 3);
  if (static_cast<size_t>(kTlsRecordHeaderLen + record_len) > data.size())
    return std::nullopt;
  size_t pos = kTlsRecordHeaderLen;
  if (data[pos] != expected_type)
    return std::nullopt;
  const uint32_t hs_len = (static_cast<uint32_t>(data[pos + 1]) << 16) |
                          (static_cast<uint32_t>(data[pos + 2]) << 8) |
                          static_cast<uint32_t>(data[pos + 3]);
  pos += kHandshakeHeaderLen;
  if (pos + hs_len > data.size())
    return std::nullopt;
  return data.subspan(pos, hs_len);
}

}  // namespace

std::string HexEncode(std::span<const uint8_t> bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.resize(bytes.size() * 2);
  for (size_t i = 0; i < bytes.size(); ++i) {
    out[i * 2] = kHex[bytes[i] >> 4];
    out[i * 2 + 1] = kHex[bytes[i] & 0x0F];
  }
  return out;
}

std::optional<TlsHandshakeInfo> ParseTlsClientHelloBody(std::span<const uint8_t> body) {
  if (body.size() < 34)
    return std::nullopt;

  size_t pos = 0;
  TlsHandshakeInfo info;
  info.is_client_hello = true;
  info.version = ReadU16Be(body.data() + pos);
  pos += 2;

  std::copy_n(body.data() + pos, 32, info.client_random.begin());
  info.has_client_random = true;
  pos += 32;

  if (pos >= body.size())
    return std::nullopt;

  const uint8_t session_id_len = body[pos++];
  pos += session_id_len;
  if (pos + 2 > body.size())
    return std::nullopt;

  const uint16_t cipher_suites_len = ReadU16Be(body.data() + pos);
  pos += 2 + cipher_suites_len;
  if (pos + 1 > body.size())
    return std::nullopt;

  const uint8_t comp_len = body[pos++];
  pos += comp_len;
  if (pos + 2 > body.size())
    return info;

  const uint16_t ext_total_len = ReadU16Be(body.data() + pos);
  pos += 2;
  size_t ext_end = pos + ext_total_len;
  if (ext_end > body.size())
    ext_end = body.size();

  while (pos + 4 <= ext_end) {
    const uint16_t ext_type = ReadU16Be(body.data() + pos);
    const uint16_t ext_len = ReadU16Be(body.data() + pos + 2);
    pos += 4;
    if (pos + ext_len > ext_end)
      break;

    if (ext_type == kExtSNI && ext_len >= 5) {
      size_t sni_pos = pos + 2;
      if (sni_pos + 3 <= pos + ext_len) {
        const uint8_t name_type = body[sni_pos++];
        if (name_type == 0) {
          const uint16_t name_len = ReadU16Be(body.data() + sni_pos);
          sni_pos += 2;
          if (sni_pos + name_len <= pos + ext_len) {
            info.sni = std::string(reinterpret_cast<const char*>(body.data() + sni_pos), name_len);
          }
        }
      }
    } else if (ext_type == kExtALPN && ext_len >= 2) {
      size_t alpn_pos = pos + 2;
      while (alpn_pos + 1 <= pos + ext_len) {
        const uint8_t proto_len = body[alpn_pos++];
        if (alpn_pos + proto_len > pos + ext_len)
          break;
        info.alpn.emplace_back(reinterpret_cast<const char*>(body.data() + alpn_pos), proto_len);
        alpn_pos += proto_len;
      }
    } else if (ext_type == kExtSupportedVersions && ext_len >= 3) {
      info.version = ReadU16Be(body.data() + pos + 1);
    }

    pos += ext_len;
  }

  return info;
}

std::optional<TlsHandshakeInfo> ParseTlsServerHelloBody(std::span<const uint8_t> body) {
  if (body.size() < 34 + 3)
    return std::nullopt;

  size_t pos = 0;
  TlsHandshakeInfo info;
  info.is_client_hello = false;
  info.version = ReadU16Be(body.data() + pos);
  pos += 2;

  std::copy_n(body.data() + pos, 32, info.server_random.begin());
  info.has_server_random = true;
  pos += 32;

  if (pos >= body.size())
    return std::nullopt;

  const uint8_t session_id_len = body[pos++];
  pos += session_id_len;
  if (pos + 2 > body.size())
    return std::nullopt;

  info.cipher_suite_id = ReadU16Be(body.data() + pos);
  info.cipher_suite = fmt::format("0x{:04X}", info.cipher_suite_id);
  pos += 2;

  if (pos >= body.size())
    return info;
  pos += 1;  // compression

  if (pos + 2 <= body.size()) {
    const uint16_t ext_total_len = ReadU16Be(body.data() + pos);
    pos += 2;
    size_t ext_end = pos + ext_total_len;
    if (ext_end > body.size())
      ext_end = body.size();

    while (pos + 4 <= ext_end) {
      const uint16_t ext_type = ReadU16Be(body.data() + pos);
      const uint16_t ext_len = ReadU16Be(body.data() + pos + 2);
      pos += 4;
      if (pos + ext_len > ext_end)
        break;

      if (ext_type == kExtSupportedVersions && ext_len >= 2) {
        info.version = ReadU16Be(body.data() + pos);
      } else if (ext_type == kExtALPN && ext_len >= 2) {
        size_t alpn_pos = pos + 2;
        while (alpn_pos + 1 <= pos + ext_len) {
          const uint8_t proto_len = body[alpn_pos++];
          if (alpn_pos + proto_len > pos + ext_len)
            break;
          info.alpn.emplace_back(reinterpret_cast<const char*>(body.data() + alpn_pos), proto_len);
          alpn_pos += proto_len;
        }
      }

      pos += ext_len;
    }
  }

  return info;
}

std::optional<TlsHandshakeInfo> ParseTlsClientHello(std::span<const uint8_t> data) {
  auto body = HandshakeBodyFromRecord(data, 0x01);
  if (!body)
    return std::nullopt;
  return ParseTlsClientHelloBody(*body);
}

std::optional<TlsHandshakeInfo> ParseTlsServerHello(std::span<const uint8_t> data) {
  auto body = HandshakeBodyFromRecord(data, 0x02);
  if (!body)
    return std::nullopt;
  return ParseTlsServerHelloBody(*body);
}

}  // namespace wirepeek::protocol
