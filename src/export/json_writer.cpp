// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/dissector/ethernet.h>
#include <wirepeek/dissector/ip.h>
#include <wirepeek/export/json_writer.h>

#include <chrono>
#include <fcntl.h>
#include <fmt/format.h>
#include <stdexcept>
#include <unistd.h>

namespace wirepeek::exporter {

JsonWriter::JsonWriter(const std::string& path) : path_(path) {
  if (path == "-") {
    fd_ = STDOUT_FILENO;
    is_stdout_ = true;
  } else {
    fd_ = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_ < 0) {
      throw std::runtime_error("Failed to open JSON file: " + path);
    }
  }
}

JsonWriter::~JsonWriter() {
  Close();
}

void JsonWriter::Close() {
  if (fd_ >= 0 && !is_stdout_) {
    ::close(fd_);
    fd_ = -1;
  }
}

void JsonWriter::Write(const std::string& line) {
  if (fd_ < 0)
    return;
  ::write(fd_, line.data(), line.size());
  ::write(fd_, "\n", 1);
  ++count_;
}

static std::string EscJson(const std::string& s) {
  std::string r;
  r.reserve(s.size());
  for (char c : s) {
    if (c == '"')
      r += "\\\"";
    else if (c == '\\')
      r += "\\\\";
    else if (c == '\n')
      r += "\\n";
    else
      r += c;
  }
  return r;
}

void JsonWriter::WritePacket(const PacketView& pkt, const dissector::DissectedPacket& dissected) {
  auto epoch_us =
      std::chrono::duration_cast<std::chrono::microseconds>(pkt.timestamp.time_since_epoch())
          .count();

  std::string json =
      fmt::format("{{\"type\":\"packet\",\"ts\":{},\"len\":{}", epoch_us, pkt.data.size());

  if (dissected.ip) {
    json += fmt::format(",\"src_ip\":\"{}\",\"dst_ip\":\"{}\"",
                        EscJson(dissector::FormatIp(dissected.ip->src_ip)),
                        EscJson(dissector::FormatIp(dissected.ip->dst_ip)));
    json += fmt::format(",\"proto\":{}", dissected.ip->protocol);
  }
  if (dissected.tcp) {
    json += fmt::format(",\"src_port\":{},\"dst_port\":{},\"tcp_flags\":{}",
                        dissected.tcp->src_port, dissected.tcp->dst_port, dissected.tcp->flags);
  }
  if (dissected.udp) {
    json += fmt::format(",\"src_port\":{},\"dst_port\":{}", dissected.udp->src_port,
                        dissected.udp->dst_port);
  }

  json += "}";
  Write(json);
}

void JsonWriter::WriteHttpTransaction(const HttpTransaction& txn) {
  auto epoch_us = std::chrono::duration_cast<std::chrono::microseconds>(
                      txn.request.timestamp.time_since_epoch())
                      .count();
  auto latency_us = txn.latency.count();

  std::string json = fmt::format(
      "{{\"type\":\"http\",\"ts\":{},\"method\":\"{}\",\"url\":\"{}\","
      "\"status\":{},\"latency_us\":{},\"req_body_size\":{},\"resp_body_size\":{},"
      "\"complete\":{}}}",
      epoch_us, EscJson(txn.request.method), EscJson(txn.request.url), txn.response.status_code,
      latency_us, txn.request.body_size, txn.response.body_size, txn.complete ? "true" : "false");

  Write(json);
}

}  // namespace wirepeek::exporter
