// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace wirepeek::protocol {

class TlsKeyLog {
 public:
  bool Load(const std::string& path, std::string* error = nullptr);
  bool ParseLine(std::string_view line);
  [[nodiscard]] size_t SecretCount() const { return secrets_.size(); }
  [[nodiscard]] const std::vector<uint8_t>* Find(std::string_view label,
                                                 std::string_view client_random) const;

 private:
  std::unordered_map<std::string, std::vector<uint8_t>> secrets_;
};

}  // namespace wirepeek::protocol
