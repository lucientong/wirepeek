// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/endian.h>
#include <wirepeek/protocol/dns.h>

#include <fmt/format.h>

namespace wirepeek::protocol {

namespace {

// DNS header is 12 bytes.
constexpr size_t kDnsHeaderLen = 12;

// Parse a DNS name from the packet, handling compression pointers.
// Returns the name and the number of bytes consumed from `data + offset`.
std::pair<std::string, size_t> ParseDnsName(std::span<const uint8_t> data, size_t offset,
                                            int max_depth = 10) {
  if (max_depth <= 0 || offset >= data.size())
    return {"", 0};

  std::string name;
  size_t consumed = 0;
  bool jumped = false;
  size_t pos = offset;

  while (pos < data.size()) {
    uint8_t len = data[pos];

    if (len == 0) {
      // End of name.
      if (!jumped)
        consumed = pos - offset + 1;
      break;
    }

    if ((len & 0xC0) == 0xC0) {
      // Compression pointer.
      if (pos + 1 >= data.size())
        break;
      if (!jumped)
        consumed = pos - offset + 2;
      uint16_t ptr = ((len & 0x3F) << 8) | data[pos + 1];
      pos = ptr;
      jumped = true;
      continue;
    }

    // Regular label.
    if (pos + 1 + len > data.size())
      break;
    if (!name.empty())
      name += '.';
    name.append(reinterpret_cast<const char*>(data.data() + pos + 1), len);
    pos += 1 + len;
    if (!jumped)
      consumed = pos - offset;
  }

  return {name, consumed};
}

}  // namespace

bool LooksDnsShaped(std::span<const uint8_t> data) {
  if (data.size() < kDnsHeaderLen)
    return false;

  // Check: QR bit, opcode, question count.
  uint16_t flags = wirepeek::ReadU16Be(data.data() + 2);
  uint8_t opcode = (flags >> 11) & 0x0F;
  uint16_t qdcount = wirepeek::ReadU16Be(data.data() + 4);

  // Standard query (opcode 0) with 1 question is most common.
  // Also accept responses (QR=1).
  return opcode <= 2 && qdcount >= 1 && qdcount <= 10 && data.size() <= 512;
}

std::optional<DnsQuery> ParseDnsQuery(std::span<const uint8_t> data) {
  if (data.size() < kDnsHeaderLen)
    return std::nullopt;

  uint16_t id = wirepeek::ReadU16Be(data.data());
  uint16_t flags = wirepeek::ReadU16Be(data.data() + 2);
  bool qr = (flags >> 15) & 1;
  if (qr)
    return std::nullopt;  // This is a response, not a query.

  uint16_t qdcount = wirepeek::ReadU16Be(data.data() + 4);
  if (qdcount == 0)
    return std::nullopt;

  // Parse first question.
  auto [name, consumed] = ParseDnsName(data, kDnsHeaderLen);
  if (name.empty() || consumed == 0)
    return std::nullopt;

  size_t pos = kDnsHeaderLen + consumed;
  if (pos + 4 > data.size())
    return std::nullopt;

  uint16_t qtype = wirepeek::ReadU16Be(data.data() + pos);

  return DnsQuery{.id = id, .name = name, .type = qtype};
}

std::optional<DnsResponse> ParseDnsResponse(std::span<const uint8_t> data) {
  if (data.size() < kDnsHeaderLen)
    return std::nullopt;

  uint16_t id = wirepeek::ReadU16Be(data.data());
  uint16_t flags = wirepeek::ReadU16Be(data.data() + 2);
  bool qr = (flags >> 15) & 1;
  if (!qr)
    return std::nullopt;  // This is a query, not a response.

  uint8_t rcode = flags & 0x0F;
  uint16_t qdcount = wirepeek::ReadU16Be(data.data() + 4);
  uint16_t ancount = wirepeek::ReadU16Be(data.data() + 6);

  // Skip question section.
  size_t pos = kDnsHeaderLen;
  std::string query_name;
  uint16_t query_type = 0;
  for (uint16_t i = 0; i < qdcount && pos < data.size(); ++i) {
    auto [name, consumed] = ParseDnsName(data, pos);
    if (consumed == 0)
      return std::nullopt;
    if (i == 0)
      query_name = name;
    pos += consumed;
    if (pos + 4 > data.size())
      return std::nullopt;
    if (i == 0)
      query_type = wirepeek::ReadU16Be(data.data() + pos);
    pos += 4;  // QTYPE + QCLASS
  }

  // Parse answer section.
  std::vector<std::string> answers;
  for (uint16_t i = 0; i < ancount && pos < data.size(); ++i) {
    auto [name, consumed] = ParseDnsName(data, pos);
    if (consumed == 0)
      break;
    pos += consumed;
    if (pos + 10 > data.size())
      break;

    uint16_t rtype = wirepeek::ReadU16Be(data.data() + pos);
    // Skip type(2) + class(2) + TTL(4).
    pos += 8;
    uint16_t rdlength = wirepeek::ReadU16Be(data.data() + pos);
    pos += 2;

    if (pos + rdlength > data.size())
      break;

    if (rtype == 1 && rdlength == 4) {
      // A record: IPv4 address.
      answers.push_back(
          fmt::format("{}.{}.{}.{}", data[pos], data[pos + 1], data[pos + 2], data[pos + 3]));
    } else if (rtype == 28 && rdlength == 16) {
      // AAAA record: IPv6 address.
      answers.push_back(fmt::format(
          "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:"
          "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
          data[pos], data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4], data[pos + 5],
          data[pos + 6], data[pos + 7], data[pos + 8], data[pos + 9], data[pos + 10],
          data[pos + 11], data[pos + 12], data[pos + 13], data[pos + 14], data[pos + 15]));
    } else if (rtype == 5) {
      // CNAME record.
      auto [cname, _] = ParseDnsName(data, pos);
      if (!cname.empty())
        answers.push_back(cname);
    }

    pos += rdlength;
  }

  return DnsResponse{
      .id = id, .name = query_name, .type = query_type, .rcode = rcode, .answers = answers};
}

}  // namespace wirepeek::protocol
