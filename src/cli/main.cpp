// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file cli/main.cpp
/// @brief Wirepeek CLI entry point.

#include <wirepeek/capture/file_source.h>
#include <wirepeek/analyzer/endpoint_stats.h>
#include <wirepeek/analyzer/metrics_server.h>
#include <wirepeek/analyzer/statistics.h>
#include <wirepeek/capture/pcap_source.h>
#include <wirepeek/dissector/dissect.h>
#include <wirepeek/dissector/tcp_reassembler.h>
#include <wirepeek/export/har_writer.h>
#include <wirepeek/export/json_writer.h>
#include <wirepeek/export/pcap_writer.h>
#include <wirepeek/protocol/protocol_handler.h>
#include <wirepeek/protocol/tls_keylog.h>
#include <wirepeek/request.h>
#include <wirepeek/tui/app.h>
#include <wirepeek/version.h>

#include <CLI/CLI.hpp>
#include <algorithm>
#include <atomic>
#include <csignal>
#include <cstdlib>
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <iostream>
#include <memory>
#include <spdlog/spdlog.h>
#include <string>
#include <type_traits>
#include <variant>

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

wirepeek::ConnectionKey MakeUdpKey(const wirepeek::dissector::DissectedPacket& packet) {
  wirepeek::ConnectionKey key;
  if (!packet.ip || !packet.udp)
    return key;
  key.ip_version = packet.ip->version;
  key.protocol = packet.ip->protocol;
  key.src_port = packet.udp->src_port;
  key.dst_port = packet.udp->dst_port;
  std::visit(
      [&key](const auto& address) {
        std::copy(address.begin(), address.end(), key.src_ip.begin());
      },
      packet.ip->src_ip);
  std::visit(
      [&key](const auto& address) {
        std::copy(address.begin(), address.end(), key.dst_ip.begin());
      },
      packet.ip->dst_ip);
  return key;
}

/// Run headless mode (tcpdump-like output).
int RunHeadless(std::unique_ptr<wirepeek::capture::CaptureSource> source, bool no_reassemble,
                int count, const std::string& export_format, const std::string& output_file,
                bool show_endpoints, const std::string& metrics_listen) {
  // Set up exporters if requested.
  std::unique_ptr<wirepeek::exporter::PcapWriter> pcap_writer;
  std::unique_ptr<wirepeek::exporter::JsonWriter> json_writer;
  std::shared_ptr<wirepeek::exporter::HarWriter> har_writer;
  auto statistics = std::make_shared<wirepeek::analyzer::Statistics>();
  auto endpoints = std::make_shared<wirepeek::analyzer::EndpointStats>(5);
  wirepeek::analyzer::MetricsServer metrics(statistics, endpoints);
  if (!metrics_listen.empty()) {
    std::string error;
    if (!metrics.Start(metrics_listen, &error)) {
      fmt::print(stderr, "Error: cannot start metrics server on {}: {}\n", metrics_listen, error);
      return 1;
    }
    fmt::print(stderr, "Metrics listening on http://{}/metrics\n", metrics_listen);
  }

  if (!export_format.empty()) {
    std::string out = output_file.empty() ? "-" : output_file;
    if (export_format == "pcap") {
      if (out == "-") {
        fmt::print(stderr, "Error: pcap export requires -o <file>\n");
        return 1;
      }
      pcap_writer = std::make_unique<wirepeek::exporter::PcapWriter>(out, source->GetLinkType());
    } else if (export_format == "json") {
      json_writer = std::make_unique<wirepeek::exporter::JsonWriter>(out);
    } else if (export_format == "har") {
      if (out == "-") {
        fmt::print(stderr, "Error: har export requires -o <file>\n");
        return 1;
      }
      har_writer = std::make_shared<wirepeek::exporter::HarWriter>();
    } else {
      fmt::print(stderr, "Error: unknown export format '{}'. Use: pcap, har, json\n",
                 export_format);
      return 1;
    }
  }

  // Set up protocol handler.
  auto protocol_handler = std::make_unique<wirepeek::protocol::ProtocolHandler>(
      [&har_writer, &json_writer, &statistics, &endpoints](const wirepeek::ConnectionKey&,
                                  const wirepeek::AppEvent& event) {
        std::visit(
            [&](const auto& value) {
              using Event = std::decay_t<decltype(value)>;
              if constexpr (std::is_same_v<Event, wirepeek::HttpTransaction>) {
                statistics->RecordHttpTransaction(value);
                endpoints->Record(value);
                if (value.complete) {
                  auto latency_ms =
                      std::chrono::duration_cast<std::chrono::milliseconds>(value.latency).count();
                  fmt::print("HTTP {} {} -> {} {} ({}ms) [{} bytes]\n", value.request.method,
                             value.request.url, value.response.status_code, value.response.reason,
                             latency_ms, value.response.body_size);
                } else {
                  fmt::print("HTTP {} {} -> (no response)\n", value.request.method,
                             value.request.url);
                }
                if (har_writer)
                  har_writer->AddTransaction(value);
                if (json_writer)
                  json_writer->WriteHttpTransaction(value);
              } else if constexpr (std::is_same_v<Event, wirepeek::RedisTransaction>) {
                fmt::print("REDIS {} {} -> {} ({}us)\n", value.command, value.args_summary,
                           value.response_summary, value.latency.count());
              } else if constexpr (std::is_same_v<Event, wirepeek::Http2StreamEvent>) {
                fmt::print("{} stream={} type={} {} {} status={}\n",
                           value.grpc ? "gRPC" : "HTTP/2", value.stream_id, value.frame_type,
                           value.method, value.path, value.status);
              } else if constexpr (std::is_same_v<Event, wirepeek::DnsEvent>) {
                fmt::print("DNS {} {} -> {} ({}us)\n", wirepeek::DnsTypeName(value.query.type),
                           value.query.name,
                           value.response && !value.response->answers.empty()
                               ? value.response->answers.front()
                               : "(no answer)",
                           value.latency.count());
              } else if constexpr (std::is_same_v<Event, wirepeek::TlsHandshakeInfo>) {
                fmt::print("TLS {} {} {}\n",
                           value.is_client_hello ? "ClientHello" : "ServerHello",
                           value.sni.empty() ? "-" : value.sni,
                           value.cipher_suite.empty() ? "" : value.cipher_suite);
              }
            },
            event);
      });

  std::unique_ptr<wirepeek::dissector::TcpReassembler> reassembler;
  if (!no_reassemble) {
    reassembler = std::make_unique<wirepeek::dissector::TcpReassembler>(
        [&protocol_handler](const wirepeek::dissector::StreamEvent& event) {
          protocol_handler->OnStreamEvent(event, event.timestamp);
        });
  }

  uint64_t packet_count = 0;

  source->Start([&](const wirepeek::PacketView& pkt) {
    if (!g_running) {
      source->Stop();
      return;
    }

    auto dissected = wirepeek::dissector::Dissect(pkt);
    statistics->RecordPacket(pkt.data.size(), pkt.timestamp);
    auto summary = wirepeek::dissector::FormatSummary(dissected);

    PrintTimestamp(pkt.timestamp);
    fmt::print("  {}\n", summary);

    // Export hooks.
    if (pcap_writer)
      pcap_writer->WritePacket(pkt);
    if (json_writer && !har_writer)
      json_writer->WritePacket(pkt, dissected);

    if (reassembler) {
      reassembler->ProcessPacket(dissected, pkt.timestamp);
    }
    if (dissected.ip && dissected.udp) {
      protocol_handler->OnUdpPayload(MakeUdpKey(dissected), dissected.udp->payload, pkt.timestamp);
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

  // Finalize exports.
  if (har_writer && !output_file.empty()) {
    har_writer->WriteToFile(output_file);
    fmt::print(stderr, "Wrote {} HTTP transactions to {}\n", har_writer->TransactionCount(),
               output_file);
  }
  if (pcap_writer) {
    fmt::print(stderr, "Wrote {} packets to {}\n", pcap_writer->PacketCount(), output_file);
  }
  if (json_writer) {
    fmt::print(stderr, "Wrote {} lines to {}\n", json_writer->LineCount(),
               output_file.empty() ? "stdout" : output_file);
  }

  if (show_endpoints) {
    fmt::print(stderr, "\n--- HTTP endpoints ---\n");
    fmt::print(stderr, "{:<9} {:<44} {:>8} {:>8} {:>10}\n", "METHOD", "ROUTE", "COUNT",
               "ERRORS", "P95(ms)");
    for (const auto& endpoint : endpoints->Snapshot()) {
      fmt::print(stderr, "{:<9} {:<44} {:>8} {:>8} {:>10.2f}\n", endpoint.method,
                 endpoint.route, endpoint.count, endpoint.error_count,
                 endpoint.p95_latency_us / 1000.0);
    }
  }

  auto stats = source->Stats();
  fmt::print(stderr, "\n--- wirepeek capture statistics ---\n");
  fmt::print(stderr, "{} packets captured\n", stats.packets_received);
  if (stats.packets_dropped > 0) {
    fmt::print(stderr, "{} packets dropped by kernel\n", stats.packets_dropped);
  }

  return 0;
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
  std::string export_format;
  std::string output_file;
  bool show_endpoints = false;
  std::string metrics_listen;
  std::string tls_keylog;

  app.add_option("-i,--interface", interface, "Network interface to capture on");
  app.add_option("-f,--filter", bpf_filter, "BPF filter expression");
  app.add_option("--read", read_file, "Read packets from a pcap file");
  app.add_flag("--headless", headless, "Headless mode (no TUI, tcpdump-like output)");
  app.add_option("-c,--count", count, "Number of packets to capture (0=unlimited)");
  app.add_flag("-v,--verbose", verbose, "Enable verbose logging");
  app.add_flag("--no-reassemble", no_reassemble, "Disable TCP stream reassembly");
  app.add_option("--export", export_format, "Export format: pcap, har, json");
  app.add_option("-o,--output", output_file, "Output file path for export");
  app.add_flag("--endpoints", show_endpoints, "Print normalized HTTP endpoint summary at exit");
  app.add_option("--metrics-listen", metrics_listen,
                 "Serve OpenMetrics on HOST:PORT (headless mode)");
  app.add_option("--tls-keylog", tls_keylog, "Read SSLKEYLOGFILE secrets (experimental)");

  CLI11_PARSE(app, argc, argv);

  spdlog::set_level(verbose ? spdlog::level::debug : spdlog::level::warn);

  if (!tls_keylog.empty()) {
    wirepeek::protocol::TlsKeyLog secrets;
    std::string error;
    if (!secrets.Load(tls_keylog, &error)) {
      fmt::print(stderr, "Error: {}\n", error);
      return 1;
    }
    fmt::print(stderr,
               "Loaded {} TLS keylog secrets; decryption is not yet implemented (experimental)\n",
               secrets.SecretCount());
  }

  if (interface.empty() && read_file.empty()) {
    fmt::print(stderr, "Error: specify either -i <interface> or --read <file>\n");
    return 1;
  }

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

  if (headless || !export_format.empty() || show_endpoints || !metrics_listen.empty()) {
    return RunHeadless(std::move(source), no_reassemble, count, export_format, output_file,
                       show_endpoints, metrics_listen);
  }

  // TUI mode.
  wirepeek::tui::TuiApp tui_app({.no_reassemble = no_reassemble});
  tui_app.Run(std::move(source));

  return 0;
}
