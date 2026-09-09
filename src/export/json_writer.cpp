// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/dissector/ethernet.h>
#include <wirepeek/dissector/ip.h>
#include <wirepeek/export/json_escape.h>
#include <wirepeek/export/json_writer.h>

#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <fmt/format.h>
#include <stdexcept>
#include <string_view>
#include <unistd.h>

namespace wirepeek::exporter {

namespace {

void WriteAll(int fd, std::string_view data) {
  while (!data.empty()) {
    const ssize_t written = ::write(fd, data.data(), data.size());
    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      throw std::runtime_error("Failed to write JSON output");
    data.remove_prefix(static_cast<size_t>(written));
  }
}

}  // namespace

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
  WriteAll(fd_, line);
  WriteAll(fd_, "\n");
  ++count_;
}

void JsonWriter::WritePacket(const PacketView& pkt, const dissector::DissectedPacket& dissected) {
  auto epoch_us =
      std::chrono::duration_cast<std::chrono::microseconds>(pkt.timestamp.time_since_epoch())
          .count();

  std::string json =
      fmt::format("{{\"type\":\"packet\",\"ts\":{},\"len\":{}", epoch_us, pkt.data.size());

  if (dissected.ip) {
    json += fmt::format(",\"src_ip\":\"{}\",\"dst_ip\":\"{}\"",
                        EscapeJson(dissector::FormatIp(dissected.ip->src_ip)),
                        EscapeJson(dissector::FormatIp(dissected.ip->dst_ip)));
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
      "\"complete\":{}",
      epoch_us, EscapeJson(txn.request.method), EscapeJson(txn.request.url),
      txn.response.status_code,
      latency_us, txn.request.body_size, txn.response.body_size, txn.complete ? "true" : "false");
  if (txn.timing.tcp_handshake)
    json += fmt::format(",\"tcp_handshake_us\":{}", txn.timing.tcp_handshake->count());
  if (txn.timing.tls_handshake)
    json += fmt::format(",\"tls_handshake_us\":{}", txn.timing.tls_handshake->count());
  if (txn.timing.ttfb)
    json += fmt::format(",\"ttfb_us\":{}", txn.timing.ttfb->count());
  if (txn.timing.transfer)
    json += fmt::format(",\"transfer_us\":{}", txn.timing.transfer->count());
  json += "}";

  Write(json);
}

}  // namespace wirepeek::exporter
