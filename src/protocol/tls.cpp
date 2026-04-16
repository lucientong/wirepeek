// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/endian.h>
#include <wirepeek/protocol/tls.h>

#include <fmt/format.h>

namespace wirepeek::protocol {

namespace {

// TLS record header: ContentType(1) + Version(2) + Length(2) = 5 bytes.
// Handshake header: HandshakeType(1) + Length(3) = 4 bytes.
// ClientHello: Version(2) + Random(32) + SessionID(1+var) + CipherSuites(2+var) +
//              Compression(1+var) + Extensions(2+var)
constexpr size_t kTlsRecordHeaderLen = 5;
constexpr size_t kHandshakeHeaderLen = 4;

// Extension types.
constexpr uint16_t kExtSNI = 0x0000;
constexpr uint16_t kExtALPN = 0x0010;
constexpr uint16_t kExtSupportedVersions = 0x002B;

}  // namespace

std::optional<TlsHandshakeInfo> ParseTlsClientHello(std::span<const uint8_t> data) {
  // Minimum: record header + handshake header + version + random.
  if (data.size() < kTlsRecordHeaderLen + kHandshakeHeaderLen + 34)
    return std::nullopt;

  // Verify TLS record: ContentType=22 (Handshake).
  if (data[0] != 0x16)
    return std::nullopt;

  size_t pos = kTlsRecordHeaderLen;

  // Handshake type: 1 = ClientHello.
  if (data[pos] != 0x01)
    return std::nullopt;
  pos += kHandshakeHeaderLen;

  TlsHandshakeInfo info;
  info.is_client_hello = true;

  // Client version.
  info.version = wirepeek::ReadU16Be(data.data() + pos);
  pos += 2;

  // Skip Random (32 bytes).
  pos += 32;
  if (pos >= data.size())
    return std::nullopt;

  // Session ID.
  uint8_t session_id_len = data[pos++];
  pos += session_id_len;
  if (pos + 2 > data.size())
    return std::nullopt;

  // Cipher suites.
  uint16_t cipher_suites_len = wirepeek::ReadU16Be(data.data() + pos);
  pos += 2 + cipher_suites_len;
  if (pos + 1 > data.size())
    return std::nullopt;

  // Compression methods.
  uint8_t comp_len = data[pos++];
  pos += comp_len;
  if (pos + 2 > data.size())
    return info;  // No extensions, still valid.

  // Extensions.
  uint16_t ext_total_len = wirepeek::ReadU16Be(data.data() + pos);
  pos += 2;
  size_t ext_end = pos + ext_total_len;
  if (ext_end > data.size())
    ext_end = data.size();

  while (pos + 4 <= ext_end) {
    uint16_t ext_type = wirepeek::ReadU16Be(data.data() + pos);
    uint16_t ext_len = wirepeek::ReadU16Be(data.data() + pos + 2);
    pos += 4;
    if (pos + ext_len > ext_end)
      break;

    if (ext_type == kExtSNI && ext_len >= 5) {
      // SNI: list_length(2) + type(1) + name_length(2) + name
      size_t sni_pos = pos + 2;  // Skip list length.
      if (sni_pos + 3 <= pos + ext_len) {
        uint8_t name_type = data[sni_pos++];
        if (name_type == 0) {  // host_name
          uint16_t name_len = wirepeek::ReadU16Be(data.data() + sni_pos);
          sni_pos += 2;
          if (sni_pos + name_len <= pos + ext_len) {
            info.sni = std::string(reinterpret_cast<const char*>(data.data() + sni_pos), name_len);
          }
        }
      }
    } else if (ext_type == kExtALPN && ext_len >= 2) {
      // ALPN: list_length(2) + (proto_length(1) + proto)*
      size_t alpn_pos = pos + 2;  // Skip list length.
      while (alpn_pos + 1 <= pos + ext_len) {
        uint8_t proto_len = data[alpn_pos++];
        if (alpn_pos + proto_len > pos + ext_len)
          break;
        info.alpn.emplace_back(reinterpret_cast<const char*>(data.data() + alpn_pos), proto_len);
        alpn_pos += proto_len;
      }
    } else if (ext_type == kExtSupportedVersions) {
      // In ClientHello: length(1) + versions list.
      if (ext_len >= 3) {
        // Use the first (highest) version.
        info.version = wirepeek::ReadU16Be(data.data() + pos + 1);
      }
    }

    pos += ext_len;
  }

  return info;
}

std::optional<TlsHandshakeInfo> ParseTlsServerHello(std::span<const uint8_t> data) {
  if (data.size() < kTlsRecordHeaderLen + kHandshakeHeaderLen + 34 + 3)
    return std::nullopt;

  if (data[0] != 0x16)
    return std::nullopt;

  size_t pos = kTlsRecordHeaderLen;

  // Handshake type: 2 = ServerHello.
  if (data[pos] != 0x02)
    return std::nullopt;
  pos += kHandshakeHeaderLen;

  TlsHandshakeInfo info;
  info.is_client_hello = false;

  // Server version.
  info.version = wirepeek::ReadU16Be(data.data() + pos);
  pos += 2;

  // Skip Random (32 bytes).
  pos += 32;
  if (pos >= data.size())
    return std::nullopt;

  // Session ID.
  uint8_t session_id_len = data[pos++];
  pos += session_id_len;
  if (pos + 2 > data.size())
    return std::nullopt;

  // Selected cipher suite.
  uint16_t cipher = wirepeek::ReadU16Be(data.data() + pos);
  info.cipher_suite = fmt::format("0x{:04X}", cipher);
  pos += 2;

  // Compression method (1 byte).
  if (pos >= data.size())
    return info;
  pos += 1;

  // Extensions (if present).
  if (pos + 2 <= data.size()) {
    uint16_t ext_total_len = wirepeek::ReadU16Be(data.data() + pos);
    pos += 2;
    size_t ext_end = pos + ext_total_len;
    if (ext_end > data.size())
      ext_end = data.size();

    while (pos + 4 <= ext_end) {
      uint16_t ext_type = wirepeek::ReadU16Be(data.data() + pos);
      uint16_t ext_len = wirepeek::ReadU16Be(data.data() + pos + 2);
      pos += 4;
      if (pos + ext_len > ext_end)
        break;

      if (ext_type == kExtSupportedVersions && ext_len >= 2) {
        info.version = wirepeek::ReadU16Be(data.data() + pos);
      }

      pos += ext_len;
    }
  }

  return info;
}

}  // namespace wirepeek::protocol
