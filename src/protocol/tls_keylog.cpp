// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/tls_keylog.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <sys/stat.h>

namespace wirepeek::protocol {
namespace {

void SecureClear(std::vector<uint8_t>& bytes) {
  if (!bytes.empty()) {
    std::fill(bytes.begin(), bytes.end(), static_cast<uint8_t>(0));
    bytes.clear();
  }
}

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

std::string ToLowerHex(std::string_view hex) {
  std::string out(hex);
  for (char& c : out)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

bool ParseTrafficGeneration(std::string_view label, std::string_view prefix, uint32_t* generation) {
  if (!label.starts_with(prefix))
    return false;
  const auto suffix = label.substr(prefix.size());
  if (suffix.empty() || !std::all_of(suffix.begin(), suffix.end(), [](char c) {
        return std::isdigit(static_cast<unsigned char>(c)) != 0;
      }))
    return false;
  *generation = static_cast<uint32_t>(std::stoul(std::string(suffix)));
  return true;
}

}  // namespace

void TlsKeyLogSecrets::Clear() {
  SecureClear(master_secret);
  SecureClear(client_handshake_traffic_secret);
  SecureClear(server_handshake_traffic_secret);
  SecureClear(client_traffic_secret_0);
  SecureClear(server_traffic_secret_0);
  for (auto& [_, value] : client_traffic_secret_n)
    SecureClear(value);
  for (auto& [_, value] : server_traffic_secret_n)
    SecureClear(value);
  client_traffic_secret_n.clear();
  server_traffic_secret_n.clear();
}

TlsKeyLog::~TlsKeyLog() {
  std::lock_guard lock(mutex_);
  for (auto& [_, secrets] : by_random_)
    secrets.Clear();
  for (auto& [_, bytes] : secrets_)
    SecureClear(bytes);
  by_random_.clear();
  secrets_.clear();
}

void TlsKeyLog::SetPath(std::string path) {
  std::lock_guard lock(mutex_);
  path_ = std::move(path);
  file_offset_ = 0;
  file_mtime_ns_ = 0;
  file_size_ = 0;
}

bool TlsKeyLog::ApplyLabel(TlsKeyLogSecrets& secrets, std::string_view label,
                           std::vector<uint8_t> value) {
  if (label == "CLIENT_RANDOM") {
    SecureClear(secrets.master_secret);
    secrets.master_secret = std::move(value);
    return true;
  }
  if (label == "CLIENT_HANDSHAKE_TRAFFIC_SECRET") {
    SecureClear(secrets.client_handshake_traffic_secret);
    secrets.client_handshake_traffic_secret = std::move(value);
    return true;
  }
  if (label == "SERVER_HANDSHAKE_TRAFFIC_SECRET") {
    SecureClear(secrets.server_handshake_traffic_secret);
    secrets.server_handshake_traffic_secret = std::move(value);
    return true;
  }
  if (label == "CLIENT_TRAFFIC_SECRET_0") {
    SecureClear(secrets.client_traffic_secret_0);
    secrets.client_traffic_secret_0 = std::move(value);
    return true;
  }
  if (label == "SERVER_TRAFFIC_SECRET_0") {
    SecureClear(secrets.server_traffic_secret_0);
    secrets.server_traffic_secret_0 = std::move(value);
    return true;
  }
  uint32_t generation = 0;
  if (ParseTrafficGeneration(label, "CLIENT_TRAFFIC_SECRET_", &generation)) {
    SecureClear(secrets.client_traffic_secret_n[generation]);
    secrets.client_traffic_secret_n[generation] = std::move(value);
    if (generation == 0) {
      SecureClear(secrets.client_traffic_secret_0);
      secrets.client_traffic_secret_0 = secrets.client_traffic_secret_n[generation];
    }
    return true;
  }
  if (ParseTrafficGeneration(label, "SERVER_TRAFFIC_SECRET_", &generation)) {
    SecureClear(secrets.server_traffic_secret_n[generation]);
    secrets.server_traffic_secret_n[generation] = std::move(value);
    if (generation == 0) {
      SecureClear(secrets.server_traffic_secret_0);
      secrets.server_traffic_secret_0 = secrets.server_traffic_secret_n[generation];
    }
    return true;
  }
  return false;
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
  if (random.size() != 64)
    return false;

  std::vector<uint8_t> bytes;
  if (!HexToBytes(secret, bytes))
    return false;
  // Accept common SSLKEYLOGFILE secret sizes (and short values used in unit tests).
  if (bytes.empty() || bytes.size() > 128)
    return false;

  const std::string random_key = ToLowerHex(random);
  std::lock_guard lock(mutex_);
  secrets_[label + '\n' + random_key] = bytes;
  ApplyLabel(by_random_[random_key], label, std::move(bytes));
  return true;
}

bool TlsKeyLog::LoadFromOffset(std::string* error) {
  if (path_.empty()) {
    if (error)
      *error = "TLS key log path is empty";
    return false;
  }

  struct stat st {};
  if (stat(path_.c_str(), &st) != 0) {
    if (error)
      *error = "cannot open TLS key log: " + path_;
    return false;
  }

  const auto mtime_ns = static_cast<std::int64_t>(st.st_mtime) * 1000000000LL
#if defined(__APPLE__)
                        + static_cast<std::int64_t>(st.st_mtimespec.tv_nsec);
#else
                        + static_cast<std::int64_t>(st.st_mtim.tv_nsec);
#endif
  const auto size = static_cast<std::uint64_t>(st.st_size);

  // Truncate / rotate: reopen from the beginning.
  if (size < file_size_ || (mtime_ns < file_mtime_ns_ && size != file_size_)) {
    file_offset_ = 0;
  }

  std::ifstream input(path_);
  if (!input) {
    if (error)
      *error = "cannot open TLS key log: " + path_;
    return false;
  }
  input.seekg(static_cast<std::streamoff>(file_offset_));
  if (!input) {
    file_offset_ = 0;
    input.clear();
    input.seekg(0);
  }

  std::string line;
  while (std::getline(input, line)) {
    // Drop trailing CR from CRLF.
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    ParseLine(line);
  }
  const auto pos = input.tellg();
  if (pos >= 0)
    file_offset_ = static_cast<std::uint64_t>(pos);
  else
    file_offset_ = size;
  file_mtime_ns_ = mtime_ns;
  file_size_ = size;
  return true;
}

bool TlsKeyLog::Load(const std::string& path, std::string* error) {
  {
    std::lock_guard lock(mutex_);
    path_ = path;
    file_offset_ = 0;
    file_mtime_ns_ = 0;
    file_size_ = 0;
  }
  return LoadFromOffset(error);
}

bool TlsKeyLog::Refresh(std::string* error) {
  std::string path_copy;
  {
    std::lock_guard lock(mutex_);
    path_copy = path_;
  }
  if (path_copy.empty()) {
    if (error)
      *error = "TLS key log path is empty";
    return false;
  }
  return LoadFromOffset(error);
}

size_t TlsKeyLog::SecretCount() const {
  std::lock_guard lock(mutex_);
  return secrets_.size();
}

size_t TlsKeyLog::SessionCount() const {
  std::lock_guard lock(mutex_);
  return by_random_.size();
}

const std::vector<uint8_t>* TlsKeyLog::Find(std::string_view label,
                                            std::string_view client_random) const {
  const std::string key = std::string(label) + '\n' + ToLowerHex(client_random);
  std::lock_guard lock(mutex_);
  const auto it = secrets_.find(key);
  return it == secrets_.end() ? nullptr : &it->second;
}

std::optional<TlsKeyLogSecrets> TlsKeyLog::Lookup(std::string_view client_random_hex) const {
  const std::string key = ToLowerHex(client_random_hex);
  std::lock_guard lock(mutex_);
  const auto it = by_random_.find(key);
  if (it == by_random_.end())
    return std::nullopt;
  return it->second;
}

}  // namespace wirepeek::protocol
