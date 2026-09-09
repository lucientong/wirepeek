// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/export/har_writer.h>
#include <wirepeek/export/json_escape.h>
#include <wirepeek/version.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <fstream>
#include <stdexcept>
#include <string_view>

namespace wirepeek::exporter {

void HarWriter::AddTransaction(const HttpTransaction& txn) {
  transactions_.push_back(txn);
}

static bool EqualsIgnoreCase(std::string_view lhs, std::string_view rhs) {
  return lhs.size() == rhs.size() &&
         std::equal(lhs.begin(), lhs.end(), rhs.begin(), [](unsigned char a, unsigned char b) {
           return std::tolower(a) == std::tolower(b);
         });
}

static std::string AbsoluteUrl(const HttpRequest& request) {
  if (request.url.starts_with("http://") || request.url.starts_with("https://"))
    return request.url;
  auto host =
      std::find_if(request.headers.begin(), request.headers.end(),
                   [](const HttpHeader& header) { return EqualsIgnoreCase(header.first, "host"); });
  if (host == request.headers.end())
    return request.url;
  return "http://" + host->second +
         (request.url.empty() || request.url.front() == '/' ? request.url : "/" + request.url);
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
    json += fmt::format("          \"url\": \"{}\",\n", EscapeJson(AbsoluteUrl(txn.request)));
    json += fmt::format("          \"httpVersion\": \"{}\",\n", EscapeJson(txn.request.version));
    json += "          \"cookies\": [],\n";
    json += "          \"queryString\": [],\n";
    json += "          \"headers\": [";
    for (size_t h = 0; h < txn.request.headers.size(); ++h) {
      if (h > 0)
        json += ", ";
      json += fmt::format("{{ \"name\": \"{}\", \"value\": \"{}\" }}",
                          EscapeJson(txn.request.headers[h].first),
                          EscapeJson(txn.request.headers[h].second));
    }
    json += "],\n";
    json += "          \"headersSize\": -1,\n";
    json += fmt::format("          \"bodySize\": {}\n", txn.request.body_size);
    json += "        },\n";

    // Response.
    json += "        \"response\": {\n";
    json += fmt::format("          \"status\": {},\n", txn.response.status_code);
    json += fmt::format("          \"statusText\": \"{}\",\n", EscapeJson(txn.response.reason));
    json += fmt::format("          \"httpVersion\": \"{}\",\n", EscapeJson(txn.response.version));
    json += "          \"cookies\": [],\n";
    json += "          \"headers\": [";
    for (size_t h = 0; h < txn.response.headers.size(); ++h) {
      if (h > 0)
        json += ", ";
      json += fmt::format("{{ \"name\": \"{}\", \"value\": \"{}\" }}",
                          EscapeJson(txn.response.headers[h].first),
                          EscapeJson(txn.response.headers[h].second));
    }
    json += "],\n";
    json += fmt::format("          \"content\": {{ \"size\": {}, \"mimeType\": \"\" }},\n",
                        txn.response.body_size);
    json += "          \"redirectURL\": \"\",\n";
    json += "          \"headersSize\": -1,\n";
    json += fmt::format("          \"bodySize\": {}\n", txn.response.body_size);
    json += "        },\n";
    json += "        \"cache\": {},\n";
    json += fmt::format("        \"timings\": {{ \"send\": 0, \"wait\": {}, \"receive\": 0 }}\n",
                        time_ms);

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
