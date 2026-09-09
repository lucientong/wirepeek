// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <wirepeek/analyzer/endpoint_stats.h>
#include <wirepeek/analyzer/statistics.h>

#include <atomic>
#include <memory>
#include <string>
#include <thread>

namespace wirepeek::analyzer {

class MetricsServer {
 public:
  MetricsServer(std::shared_ptr<Statistics> statistics,
                std::shared_ptr<EndpointStats> endpoints);
  ~MetricsServer();

  bool Start(const std::string& address, std::string* error = nullptr);
  void Stop();
  [[nodiscard]] std::string Render() const;

 private:
  void Serve();

  std::shared_ptr<Statistics> statistics_;
  std::shared_ptr<EndpointStats> endpoints_;
  std::atomic<bool> running_{false};
  int listen_fd_ = -1;
  std::thread thread_;
};

}  // namespace wirepeek::analyzer
