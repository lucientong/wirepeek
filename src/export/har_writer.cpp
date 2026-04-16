// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/export/har_writer.h>
#include <wirepeek/version.h>

#include <chrono>
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <fstream>
#include <stdexcept>

namespace wirepeek::exporter {

void HarWriter::AddTransaction(const HttpTransaction& txn) {
  transactions_.push_back(txn);
}

static std::string EscapeJson(const std::string& s) {
  std::string result;
  result.reserve(s.size());
  for (char c : s) {
    switch (c) {
      case '"':
        result += "\\\"";
        break;
      case '\\':
        result += "\\\\";
        break;
      case '\n':
        result += "\\n";
        break;
      case '\r':
        result += "\\r";
        break;
      case '\t':
        result += "\\t";
        break;
      default:
        result += c;
    }
  }
  return result;
}

static std::string FormatIsoTime(Timestamp ts) {
  auto time_t_val = std::chrono::system_clock::to_time_t(ts);
  std::tm tm_val;
  gmtime_r(&time_t_val, &tm_val);
  auto us = std::chrono::duration_cast<std::chrono::microseconds>(ts.time_since_epoch()) %
            std::chrono::seconds(1);
  return fmt::format("{:%Y-%m-%dT%H:%M:%S}.{:03d}Z", tm_val, us.count() / 1000);
}

std::string HarWriter::ToJson() const {
  std::string json = "{\n  \"log\": {\n    \"version\": \"1.2\",\n";
  json += fmt::format("    \"creator\": {{ \"name\": \"wirepeek\", \"version\": \"{}\" }},\n",
                      WIREPEEK_VERSION);
  json += "    \"entries\": [\n";

  for (size_t i = 0; i < transactions_.size(); ++i) {
    const auto& txn = transactions_[i];
    auto time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(txn.latency).count();

    json += "      {\n";
    json +=
        fmt::format("        \"startedDateTime\": \"{}\",\n", FormatIsoTime(txn.request.timestamp));
    json += fmt::format("        \"time\": {},\n", time_ms);

    // Request.
    json += "        \"request\": {\n";
    json += fmt::format("          \"method\": \"{}\",\n", EscapeJson(txn.request.method));
    json += fmt::format("          \"url\": \"{}\",\n", EscapeJson(txn.request.url));
    json += fmt::format("          \"httpVersion\": \"{}\",\n", EscapeJson(txn.request.version));
    json += "          \"headers\": [";
    for (size_t h = 0; h < txn.request.headers.size(); ++h) {
      if (h > 0)
        json += ", ";
      json += fmt::format("{{ \"name\": \"{}\", \"value\": \"{}\" }}",
                          EscapeJson(txn.request.headers[h].first),
                          EscapeJson(txn.request.headers[h].second));
    }
    json += "],\n";
    json += fmt::format("          \"bodySize\": {}\n", txn.request.body_size);
    json += "        },\n";

    // Response.
    json += "        \"response\": {\n";
    json += fmt::format("          \"status\": {},\n", txn.response.status_code);
    json += fmt::format("          \"statusText\": \"{}\",\n", EscapeJson(txn.response.reason));
    json += fmt::format("          \"httpVersion\": \"{}\",\n", EscapeJson(txn.response.version));
    json += "          \"headers\": [";
    for (size_t h = 0; h < txn.response.headers.size(); ++h) {
      if (h > 0)
        json += ", ";
      json += fmt::format("{{ \"name\": \"{}\", \"value\": \"{}\" }}",
                          EscapeJson(txn.response.headers[h].first),
                          EscapeJson(txn.response.headers[h].second));
    }
    json += "],\n";
    json += fmt::format("          \"bodySize\": {}\n", txn.response.body_size);
    json += "        }\n";

    json += "      }";
    if (i + 1 < transactions_.size())
      json += ",";
    json += "\n";
  }

  json += "    ]\n  }\n}\n";
  return json;
}

void HarWriter::WriteToFile(const std::string& path) const {
  std::ofstream file(path);
  if (!file.is_open()) {
    throw std::runtime_error("Failed to open HAR file: " + path);
  }
  file << ToJson();
}

}  // namespace wirepeek::exporter
