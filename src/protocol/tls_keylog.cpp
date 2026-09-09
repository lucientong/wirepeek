// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/tls_keylog.h>

#include <cctype>
#include <fstream>
#include <sstream>

namespace wirepeek::protocol {
namespace {

bool HexToBytes(std::string_view hex, std::vector<uint8_t>& bytes) {
  if (hex.empty() || hex.size() % 2 != 0)
    return false;
  bytes.clear();
  bytes.reserve(hex.size() / 2);
  auto digit = [](char c) -> int {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < hex.size(); i += 2) {
    const int hi = digit(hex[i]);
    const int lo = digit(hex[i + 1]);
    if (hi < 0 || lo < 0)
      return false;
    bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return true;
}

}  // namespace

bool TlsKeyLog::Load(const std::string& path, std::string* error) {
  std::ifstream input(path);
  if (!input) {
    if (error)
      *error = "cannot open TLS key log: " + path;
    return false;
  }
  std::string line;
  while (std::getline(input, line))
    ParseLine(line);
  return true;
}

bool TlsKeyLog::ParseLine(std::string_view line) {
  while (!line.empty() && std::isspace(static_cast<unsigned char>(line.front())))
    line.remove_prefix(1);
  if (line.empty() || line.front() == '#')
    return false;

  std::istringstream stream{std::string(line)};
  std::string label;
  std::string random;
  std::string secret;
  std::string extra;
  if (!(stream >> label >> random >> secret) || (stream >> extra))
    return false;
  std::vector<uint8_t> bytes;
  if (random.size() != 64 || !HexToBytes(secret, bytes))
    return false;
  secrets_[label + '\n' + random] = std::move(bytes);
  return true;
}

const std::vector<uint8_t>* TlsKeyLog::Find(std::string_view label,
                                            std::string_view client_random) const {
  const auto it = secrets_.find(std::string(label) + '\n' + std::string(client_random));
  return it == secrets_.end() ? nullptr : &it->second;
}

}  // namespace wirepeek::protocol
