// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/analyzer/metrics_server.h>

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fmt/format.h>
#include <netdb.h>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>

namespace wirepeek::analyzer {
namespace {

std::string EscapeLabel(std::string_view value) {
  std::string escaped;
  escaped.reserve(value.size());
  for (char c : value) {
    if (c == '\\' || c == '"')
      escaped.push_back('\\');
    if (c == '\n') {
      escaped += "\\n";
    } else {
      escaped.push_back(c);
    }
  }
  return escaped;
}

void SendAll(int fd, std::string_view data) {
  while (!data.empty()) {
    const ssize_t sent = ::send(fd, data.data(), data.size(), 0);
    if (sent < 0 && errno == EINTR)
      continue;
    if (sent <= 0)
      return;
    data.remove_prefix(static_cast<size_t>(sent));
  }
}

}  // namespace

MetricsServer::MetricsServer(std::shared_ptr<Statistics> statistics,
                             std::shared_ptr<EndpointStats> endpoints)
    : statistics_(std::move(statistics)), endpoints_(std::move(endpoints)) {}

MetricsServer::~MetricsServer() {
  Stop();
}

bool MetricsServer::Start(const std::string& address, std::string* error) {
  const auto colon = address.rfind(':');
  if (colon == std::string::npos || colon + 1 == address.size()) {
    if (error)
      *error = "metrics address must be HOST:PORT";
    return false;
  }
  std::string host = address.substr(0, colon);
  const std::string port = address.substr(colon + 1);
  if (host.empty())
    host = "0.0.0.0";

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  addrinfo* addresses = nullptr;
  const int lookup = ::getaddrinfo(host.c_str(), port.c_str(), &hints, &addresses);
  if (lookup != 0) {
    if (error)
      *error = ::gai_strerror(lookup);
    return false;
  }

  for (auto* candidate = addresses; candidate != nullptr; candidate = candidate->ai_next) {
    listen_fd_ = ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (listen_fd_ < 0)
      continue;
    int reuse = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (::bind(listen_fd_, candidate->ai_addr, candidate->ai_addrlen) == 0 &&
        ::listen(listen_fd_, 16) == 0)
      break;
    ::close(listen_fd_);
    listen_fd_ = -1;
  }
  ::freeaddrinfo(addresses);
  if (listen_fd_ < 0) {
    if (error)
      *error = std::strerror(errno);
    return false;
  }

  running_ = true;
  thread_ = std::thread(&MetricsServer::Serve, this);
  return true;
}

void MetricsServer::Stop() {
  running_ = false;
  if (listen_fd_ >= 0) {
    ::shutdown(listen_fd_, SHUT_RDWR);
    ::close(listen_fd_);
    listen_fd_ = -1;
  }
  if (thread_.joinable())
    thread_.join();
}

std::string MetricsServer::Render() const {
  const auto stats = statistics_->Snapshot();
  std::string output;
  output += "# TYPE wirepeek_http_requests_total counter\n";
  for (const auto& endpoint : endpoints_->Snapshot()) {
    for (size_t status_class = 0; status_class < endpoint.status_class_counts.size();
         ++status_class) {
      const auto count = endpoint.status_class_counts[status_class];
      if (count == 0)
        continue;
      output += fmt::format(
          "wirepeek_http_requests_total{{method=\"{}\",route=\"{}\",status_class=\"{}xx\"}} {}\n",
          EscapeLabel(endpoint.method), EscapeLabel(endpoint.route), status_class, count);
    }
  }
  output += "# TYPE wirepeek_http_latency_seconds gauge\n";
  output += fmt::format("wirepeek_http_latency_seconds{{quantile=\"0.5\"}} {:.6f}\n",
                        stats.p50_latency_us / 1'000'000.0);
  output += fmt::format("wirepeek_http_latency_seconds{{quantile=\"0.95\"}} {:.6f}\n",
                        stats.p95_latency_us / 1'000'000.0);
  output += fmt::format("wirepeek_http_latency_seconds{{quantile=\"0.99\"}} {:.6f}\n",
                        stats.p99_latency_us / 1'000'000.0);
  output += "# TYPE wirepeek_packets_total counter\n";
  output += fmt::format("wirepeek_packets_total {}\n", stats.total_packets);
  output += "# EOF\n";
  return output;
}

void MetricsServer::Serve() {
  while (running_) {
    const int client = ::accept(listen_fd_, nullptr, nullptr);
    if (client < 0) {
      if (running_ && errno == EINTR)
        continue;
      break;
    }
    char request[4096];
    const ssize_t received = ::recv(client, request, sizeof(request), 0);
    const bool metrics =
        received > 0 &&
        std::string_view(request, static_cast<size_t>(received)).starts_with("GET /metrics ");
    const std::string body = metrics ? Render() : "not found\n";
    const std::string response = fmt::format(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        metrics ? 200 : 404, metrics ? "OK" : "Not Found",
        metrics ? "application/openmetrics-text; version=1.0.0; charset=utf-8" : "text/plain",
        body.size(), body);
    SendAll(client, response);
    ::close(client);
  }
}

}  // namespace wirepeek::analyzer
