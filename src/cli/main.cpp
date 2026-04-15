// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file cli/main.cpp
/// @brief Wirepeek CLI entry point.

#include <wirepeek/capture/file_source.h>
#include <wirepeek/capture/pcap_source.h>
#include <wirepeek/dissector/dissect.h>

#include <CLI/CLI.hpp>
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

namespace {

// Global flag for signal handling.
std::atomic<bool> g_running{true};

void SignalHandler(int /*signum*/) {
  g_running = false;
}

}  // namespace

int main(int argc, char* argv[]) {
  CLI::App app{"wirepeek - High-performance network packet analyzer"};

  std::string interface;
  std::string bpf_filter;
  std::string read_file;
  bool headless = false;
  int count = 0;  // 0 = unlimited
  bool verbose = false;

  app.add_option("-i,--interface", interface, "Network interface to capture on");
  app.add_option("-f,--filter", bpf_filter, "BPF filter expression");
  app.add_option("--read", read_file, "Read packets from a pcap file");
  app.add_flag("--headless", headless, "Headless mode (no TUI, tcpdump-like output)");
  app.add_option("-c,--count", count, "Number of packets to capture (0=unlimited)");
  app.add_flag("-v,--verbose", verbose, "Enable verbose logging");

  CLI11_PARSE(app, argc, argv);

  // Configure logging.
  spdlog::set_level(verbose ? spdlog::level::debug : spdlog::level::warn);

  // Validate arguments.
  if (interface.empty() && read_file.empty()) {
    fmt::print(stderr, "Error: specify either -i <interface> or --read <file>\n");
    return 1;
  }

  // For now, always run in headless mode (TUI comes in Phase 4).
  headless = true;

  // Set up signal handling.
  std::signal(SIGINT, SignalHandler);
  std::signal(SIGTERM, SignalHandler);

  // Create the capture source.
  std::unique_ptr<wirepeek::capture::CaptureSource> source;
  try {
    if (!read_file.empty()) {
      source = std::make_unique<wirepeek::capture::FileSource>(read_file);
    } else {
      wirepeek::capture::PcapConfig config{
          .interface = interface,
          .bpf_filter = bpf_filter,
      };
      source = std::make_unique<wirepeek::capture::PcapSource>(std::move(config));
    }
  } catch (const std::exception& e) {
    fmt::print(stderr, "Error: {}\n", e.what());
    return 1;
  }

  // Capture and dissect packets.
  uint64_t packet_count = 0;

  source->Start([&](const wirepeek::PacketView& pkt) {
    if (!g_running) {
      source->Stop();
      return;
    }

    auto dissected = wirepeek::dissector::Dissect(pkt);
    auto summary = wirepeek::dissector::FormatSummary(dissected);

    // Format timestamp as HH:MM:SS.microseconds.
    auto sys_time = pkt.timestamp;
    auto time_t_val = std::chrono::system_clock::to_time_t(sys_time);
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                  sys_time.time_since_epoch()) %
              std::chrono::seconds(1);
    std::tm tm_val;
    localtime_r(&time_t_val, &tm_val);

    fmt::print("{:%H:%M:%S}.{:06d}  {}\n", tm_val, us.count(), summary);

    ++packet_count;
    if (count > 0 && packet_count >= static_cast<uint64_t>(count)) {
      source->Stop();
    }
  });

  // Print statistics.
  auto stats = source->Stats();
  fmt::print(stderr, "\n--- wirepeek capture statistics ---\n");
  fmt::print(stderr, "{} packets captured\n", stats.packets_received);
  if (stats.packets_dropped > 0) {
    fmt::print(stderr, "{} packets dropped by kernel\n", stats.packets_dropped);
  }

  return 0;
}
