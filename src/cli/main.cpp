// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file cli/main.cpp
/// @brief Wirepeek CLI entry point.

#include <wirepeek/capture/file_source.h>
#include <wirepeek/capture/pcap_source.h>
#include <wirepeek/dissector/dissect.h>
#include <wirepeek/dissector/tcp_reassembler.h>
#include <wirepeek/protocol/protocol_handler.h>
#include <wirepeek/request.h>

#include <CLI/CLI.hpp>
#include <atomic>
#include <csignal>
#include <cstdlib>
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <iostream>
#include <memory>
#include <spdlog/spdlog.h>
#include <string>

namespace {

std::atomic<bool> g_running{true};

void SignalHandler(int /*signum*/) {
  g_running = false;
}

void PrintTimestamp(wirepeek::Timestamp ts) {
  auto time_t_val = std::chrono::system_clock::to_time_t(ts);
  auto us = std::chrono::duration_cast<std::chrono::microseconds>(ts.time_since_epoch()) %
            std::chrono::seconds(1);
  std::tm tm_val;
  localtime_r(&time_t_val, &tm_val);
  fmt::print("{:%H:%M:%S}.{:06d}", tm_val, us.count());
}

}  // namespace

int main(int argc, char* argv[]) {
  CLI::App app{"wirepeek - High-performance network packet analyzer"};

  std::string interface;
  std::string bpf_filter;
  std::string read_file;
  bool headless = false;
  int count = 0;
  bool verbose = false;
  bool no_reassemble = false;

  app.add_option("-i,--interface", interface, "Network interface to capture on");
  app.add_option("-f,--filter", bpf_filter, "BPF filter expression");
  app.add_option("--read", read_file, "Read packets from a pcap file");
  app.add_flag("--headless", headless, "Headless mode (no TUI, tcpdump-like output)");
  app.add_option("-c,--count", count, "Number of packets to capture (0=unlimited)");
  app.add_flag("-v,--verbose", verbose, "Enable verbose logging");
  app.add_flag("--no-reassemble", no_reassemble, "Disable TCP stream reassembly");

  CLI11_PARSE(app, argc, argv);

  spdlog::set_level(verbose ? spdlog::level::debug : spdlog::level::warn);

  if (interface.empty() && read_file.empty()) {
    fmt::print(stderr, "Error: specify either -i <interface> or --read <file>\n");
    return 1;
  }

  headless = true;

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

  // Set up protocol handler for HTTP transaction display.
  auto protocol_handler = std::make_unique<wirepeek::protocol::ProtocolHandler>(
      // HTTP transaction callback.
      [](const wirepeek::ConnectionKey& /*key*/, const wirepeek::HttpTransaction& txn) {
        if (txn.complete) {
          auto latency_ms =
              std::chrono::duration_cast<std::chrono::milliseconds>(txn.latency).count();
          fmt::print("{} {} {} -> {} {} ({}ms) [{} bytes]\n", txn.request.method, txn.request.url,
                     txn.request.version, txn.response.status_code, txn.response.reason, latency_ms,
                     txn.response.body_size);
        } else {
          fmt::print("{} {} {} -> (no response)\n", txn.request.method, txn.request.url,
                     txn.request.version);
        }
      },
      // Raw data fallback callback.
      [](const wirepeek::ConnectionKey& /*key*/, wirepeek::StreamDirection dir,
         std::span<const uint8_t> data) {
        const char* dir_str = (dir == wirepeek::StreamDirection::kClientToServer)
                                  ? "client->server"
                                  : "server->client";
        fmt::print("[stream data] {} bytes ({})\n", data.size(), dir_str);
      });

  // Set up TCP reassembler.
  std::unique_ptr<wirepeek::dissector::TcpReassembler> reassembler;
  if (!no_reassemble) {
    reassembler = std::make_unique<wirepeek::dissector::TcpReassembler>(
        [&protocol_handler](const wirepeek::dissector::StreamEvent& event) {
          // Use the event's timestamp or a default.
          auto now = std::chrono::time_point_cast<std::chrono::microseconds>(
              std::chrono::system_clock::now());
          protocol_handler->OnStreamEvent(event, now);
        });
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

    PrintTimestamp(pkt.timestamp);
    fmt::print("  {}\n", summary);

    if (reassembler) {
      reassembler->ProcessPacket(dissected, pkt.timestamp);
    }

    ++packet_count;
    if (count > 0 && packet_count >= static_cast<uint64_t>(count)) {
      source->Stop();
    }
  });

  if (reassembler) {
    auto now =
        std::chrono::time_point_cast<std::chrono::microseconds>(std::chrono::system_clock::now());
    reassembler->FlushExpired(now);
    fmt::print(stderr, "{} active TCP streams at exit\n", reassembler->StreamCount());
  }

  auto stats = source->Stats();
  fmt::print(stderr, "\n--- wirepeek capture statistics ---\n");
  fmt::print(stderr, "{} packets captured\n", stats.packets_received);
  if (stats.packets_dropped > 0) {
    fmt::print(stderr, "{} packets dropped by kernel\n", stats.packets_dropped);
  }

  return 0;
}
