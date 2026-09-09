// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/analyzer/endpoint_stats.h>
#include <wirepeek/analyzer/statistics.h>
#include <wirepeek/dissector/dissect.h>
#include <wirepeek/dissector/tcp_reassembler.h>
#include <wirepeek/protocol/dns.h>
#include <wirepeek/protocol/protocol_handler.h>
#include <wirepeek/request.h>
#include <wirepeek/tui/app.h>
#include <wirepeek/version.h>

#include <algorithm>
#include <chrono>
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/loop.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <iterator>
#include <spdlog/spdlog.h>
#include <thread>
#include <type_traits>
#include <variant>
#include <vector>

namespace wirepeek::tui {

namespace {

std::string FormatTimestamp(Timestamp ts) {
  auto time_t_val = std::chrono::system_clock::to_time_t(ts);
  auto us = std::chrono::duration_cast<std::chrono::microseconds>(ts.time_since_epoch()) %
            std::chrono::seconds(1);
  std::tm tm_val;
  localtime_r(&time_t_val, &tm_val);
  return fmt::format("{:%H:%M:%S}.{:03d}", tm_val, us.count() / 1000);
}

ftxui::Color StatusColor(uint16_t code) {
  if (code == 0)
    return ftxui::Color::GrayDark;
  if (code < 300)
    return ftxui::Color::Green;
  if (code < 400)
    return ftxui::Color::Yellow;
  if (code < 500)
    return ftxui::Color::RedLight;
  return ftxui::Color::Red;
}

ftxui::Color ProtocolColor(const std::string& proto) {
  if (proto == "HTTP")
    return ftxui::Color::Cyan;
  if (proto == "TLS")
    return ftxui::Color::Yellow;
  if (proto == "TCP")
    return ftxui::Color::Blue;
  if (proto == "UDP")
    return ftxui::Color::Magenta;
  if (proto == "DNS")
    return ftxui::Color::Green;
  return ftxui::Color::GrayLight;
}

ConnectionKey MakeUdpKey(const dissector::DissectedPacket& packet) {
  ConnectionKey key;
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

// Sparkline chars: ▁▂▃▄▅▆▇█
const char* SparkChar(int value, int max_val) {
  if (max_val <= 0)
    return " ";
  static const char* chars[] = {"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};
  int idx = std::clamp(value * 7 / std::max(max_val, 1), 0, 7);
  return chars[idx];
}

}  // namespace

TuiApp::TuiApp(TuiConfig config) : config_(config), state_(std::make_shared<UiState>()) {}

TuiApp::~TuiApp() {
  running_ = false;
}

void TuiApp::CaptureLoop(capture::CaptureSource& source) {
  auto stats = std::make_shared<analyzer::Statistics>();
  auto endpoints = std::make_shared<analyzer::EndpointStats>(5);

  auto protocol_handler = std::make_unique<protocol::ProtocolHandler>(
      [this, stats, endpoints](const ConnectionKey&, const AppEvent& event) {
        TuiEntry entry;
        std::visit(
            [&](const auto& value) {
              using Event = std::decay_t<decltype(value)>;
              if constexpr (std::is_same_v<Event, HttpTransaction>) {
                state_->IncrementHttpTransactions();
                stats->RecordHttpTransaction(value);
                endpoints->Record(value);
                state_->SetEndpoints(endpoints->Snapshot());
                entry.timestamp = value.request.timestamp;
                entry.protocol = "HTTP";
                entry.method = value.request.method;
                entry.url = value.request.url;
                entry.status = value.response.status_code;
                if (value.complete) {
                  entry.latency = fmt::format("{}ms", value.latency.count() / 1000);
                  entry.size = fmt::format("{}", value.response.body_size);
                  entry.detail = fmt::format("{} {} {}\n", value.request.method, value.request.url,
                                             value.request.version);
                  for (const auto& [name, header_value] : value.request.headers)
                    entry.detail += fmt::format("{}: {}\n", name, header_value);
                  entry.detail +=
                      fmt::format("\n-> {} {} (Content-Length: {})\n", value.response.status_code,
                                  value.response.reason, value.response.body_size);
                  for (const auto& [name, header_value] : value.response.headers)
                    entry.detail += fmt::format("{}: {}\n", name, header_value);
                  entry.detail += "\nTiming:\n";
                  if (value.timing.tcp_handshake)
                    entry.detail +=
                        fmt::format("TCP handshake: {}us\n", value.timing.tcp_handshake->count());
                  if (value.timing.tls_handshake)
                    entry.detail +=
                        fmt::format("TLS handshake: {}us\n", value.timing.tls_handshake->count());
                  if (value.timing.ttfb)
                    entry.detail += fmt::format("TTFB: {}us\n", value.timing.ttfb->count());
                  if (value.timing.transfer)
                    entry.detail += fmt::format("Transfer: {}us\n", value.timing.transfer->count());
                } else {
                  entry.detail = fmt::format("{} {} {}\n(no response)\n", value.request.method,
                                             value.request.url, value.request.version);
                }
              } else if constexpr (std::is_same_v<Event, RedisTransaction>) {
                entry.timestamp = value.timestamp;
                entry.protocol = "Redis";
                entry.method = value.command;
                entry.url = value.args_summary;
                entry.latency = fmt::format("{}ms", value.latency.count() / 1000);
                entry.detail = fmt::format("{} {}\n-> {}\n", value.command, value.args_summary,
                                           value.response_summary);
              } else if constexpr (std::is_same_v<Event, Http2StreamEvent>) {
                entry.timestamp = value.timestamp;
                entry.protocol = value.grpc ? "gRPC" : "HTTP/2";
                entry.method = value.method;
                entry.url =
                    value.path.empty() ? fmt::format("stream {}", value.stream_id) : value.path;
                entry.status = value.status;
                entry.size = fmt::format("{}", value.payload_size);
                entry.detail = fmt::format("HTTP/2 stream {}\nFrame type: {}\nFlags: 0x{:02x}\n",
                                           value.stream_id, value.frame_type, value.flags);
              } else if constexpr (std::is_same_v<Event, DnsEvent>) {
                entry.timestamp = value.query.timestamp;
                entry.protocol = "DNS";
                entry.method = DnsTypeName(value.query.type);
                entry.url = value.query.name;
                entry.latency = fmt::format("{}ms", value.latency.count() / 1000);
                entry.detail =
                    fmt::format("DNS {} {} rcode={}\n", DnsTypeName(value.query.type),
                                value.query.name, value.response ? value.response->rcode : 0);
                if (value.response) {
                  for (const auto& answer : value.response->answers)
                    entry.detail += fmt::format("{}\n", answer);
                }
              } else if constexpr (std::is_same_v<Event, TlsHandshakeInfo>) {
                entry.timestamp = value.timestamp;
                entry.protocol = "TLS";
                entry.method = value.is_client_hello ? "Client" : "Server";
                entry.url = !value.sni.empty() ? value.sni : value.cipher_suite;
                entry.detail =
                    fmt::format("{}\nVersion: {}\nSNI: {}\nCipher: {}\n",
                                value.is_client_hello ? "ClientHello" : "ServerHello",
                                TlsVersionName(value.version), value.sni, value.cipher_suite);
              } else if constexpr (std::is_same_v<Event, WebSocketEvent>) {
                entry.timestamp = std::chrono::time_point_cast<std::chrono::microseconds>(
                    std::chrono::system_clock::now());
                entry.protocol = "WS";
                entry.url = WsOpcodeName(value.frame.opcode);
                entry.size = fmt::format("{}", value.frame.payload_len);
                entry.detail = fmt::format("WebSocket {} frame\nFIN: {}\nMasked: {}\nBytes: {}\n",
                                           WsOpcodeName(value.frame.opcode), value.frame.fin,
                                           value.frame.masked, value.frame.payload_len);
              } else if constexpr (std::is_same_v<Event, RawFlowEvent>) {
                entry.timestamp = value.ts;
                entry.protocol = value.protocol == AppProtocol::kHttp2 ? "HTTP/2" : "TCP";
                entry.url = value.dir == StreamDirection::kClientToServer ? "client->server"
                                                                          : "server->client";
                entry.size = fmt::format("{}", value.bytes);
                entry.detail = fmt::format("{} data: {} bytes\n", AppProtocolName(value.protocol),
                                           value.bytes);
              }
            },
            event);
        state_->AddEntry(std::move(entry));
      });

  std::unique_ptr<dissector::TcpReassembler> reassembler;
  if (!config_.no_reassemble) {
    reassembler = std::make_unique<dissector::TcpReassembler>(
        [&protocol_handler, stats](const dissector::StreamEvent& event) {
          if (event.type == dissector::StreamEventType::kOpen)
            stats->RecordStreamOpen();
          else if (event.type == dissector::StreamEventType::kClose)
            stats->RecordStreamClose();
          protocol_handler->OnStreamEvent(event, event.timestamp);
        });
  }

  // PPS tracking for sparkline.
  int pps_counter = 0;
  auto last_pps_push = std::chrono::steady_clock::now();

  source.Start([&](const PacketView& pkt) {
    if (!running_) {
      source.Stop();
      return;
    }

    state_->IncrementPackets(pkt.data.size());
    stats->RecordPacket(pkt.data.size(), pkt.timestamp);
    ++pps_counter;

    // Push PPS sample every second.
    auto now_steady = std::chrono::steady_clock::now();
    if (now_steady - last_pps_push >= std::chrono::seconds(1)) {
      state_->PushPpsSample(pps_counter);
      pps_counter = 0;
      last_pps_push = now_steady;
      auto snap = stats->Snapshot(pkt.timestamp);
      state_->UpdateAnalyzerStats(snap.p50_latency_us, snap.p95_latency_us, snap.p99_latency_us,
                                  snap.throughput_mbps, snap.qps);
      if (reassembler) {
        reassembler->FlushExpired(pkt.timestamp);
      }
    }

    auto dissected = dissector::Dissect(pkt);

    if (dissected.ip && dissected.udp) {
      protocol_handler->OnUdpPayload(MakeUdpKey(dissected), dissected.udp->payload, pkt.timestamp);
    }

    if (reassembler) {
      reassembler->ProcessPacket(dissected, pkt.timestamp);
      state_->SetStreamCount(reassembler->StreamCount());
    }

    if (!dissected.tcp && dissected.ip) {
      TuiEntry entry;
      entry.timestamp = pkt.timestamp;
      if (dissected.udp && dissected.udp->src_port != 53 && dissected.udp->dst_port != 53 &&
          !protocol::LooksDnsShaped(dissected.udp->payload)) {
        entry.protocol = "UDP";
        entry.url = fmt::format("port {} -> {}", dissected.udp->src_port, dissected.udp->dst_port);
        entry.size = fmt::format("{}", dissected.udp->payload.size());
      } else if (!dissected.udp) {
        entry.protocol = fmt::format("proto={}", dissected.ip->protocol);
        entry.url = dissector::FormatSummary(dissected);
      }
      if (!entry.protocol.empty())
        state_->AddEntry(std::move(entry));
    }
  });
}

void TuiApp::Run(std::unique_ptr<capture::CaptureSource> source) {
  running_ = true;

  auto screen = ftxui::ScreenInteractive::Fullscreen();

  std::thread capture_thread([this, &source]() {
    CaptureLoop(*source);
    running_ = false;
  });

  int selected = 0;
  bool show_detail = true;
  bool follow = true;
  int detail_scroll = 0;
  bool filter_active = false;
  bool endpoint_view = false;
  std::string filter_text;
  std::vector<TuiEntry> cached_entries;
  TuiStats cached_stats;

  auto component = ftxui::Renderer([&]() {
    if (filter_text.empty()) {
      cached_entries = state_->GetEntries();
    } else {
      cached_entries = state_->GetFilteredEntries(filter_text);
    }
    cached_stats = state_->GetStats();

    using namespace ftxui;

    // ── Stats bar with sparkline ──
    auto p95_str = cached_stats.p95_latency_us > 0
                       ? fmt::format("{}ms", cached_stats.p95_latency_us / 1000)
                       : "-";
    auto tp_str = cached_stats.throughput_mbps > 0.01
                      ? fmt::format("{:.1f}Mbps", cached_stats.throughput_mbps)
                      : "-";

    // Build sparkline string.
    std::string sparkline;
    int max_pps = 1;
    for (int v : cached_stats.pps_history)
      max_pps = std::max(max_pps, v);
    for (int v : cached_stats.pps_history)
      sparkline += SparkChar(v, max_pps);

    auto stats_bar = hbox({
                         text(" Pkts:") | bold,
                         text(fmt::format("{}", cached_stats.packet_count)) | color(Color::Cyan),
                         text(" Strm:") | bold,
                         text(fmt::format("{}", cached_stats.stream_count)) | color(Color::Yellow),
                         text(" HTTP:") | bold,
                         text(fmt::format("{}", cached_stats.http_txn_count)) | color(Color::Green),
                         text(" P95:") | bold,
                         text(p95_str) | color(Color::Magenta),
                         separator(),
                         text(sparkline) | color(Color::GreenLight) | size(WIDTH, LESS_THAN, 30),
                         filler(),
                         text(tp_str) | color(Color::CyanLight),
                         text(" wirepeek ") | bold | color(Color::Cyan),
                     }) |
                     borderLight;

    // ── Filter bar ──
    Element filter_bar_el = text("");
    if (filter_active || !filter_text.empty()) {
      filter_bar_el =
          hbox({
              text(" Filter: ") | bold | color(Color::Yellow),
              text(filter_text + (filter_active ? "▏" : "")) | color(Color::White),
              filler(),
              text(fmt::format(" {}/{}", cached_entries.size(), state_->EntryCount())) | dim,
          }) |
          borderLight;
    }

    // ── Request table ──
    std::vector<Element> table_rows;
    table_rows.push_back(hbox({
        text("Time") | size(WIDTH, EQUAL, 12) | bold,
        separator(),
        text("Proto") | size(WIDTH, EQUAL, 6) | bold,
        separator(),
        text("Method") | size(WIDTH, EQUAL, 7) | bold,
        separator(),
        text("URL / Endpoint") | flex | bold,
        separator(),
        text("Status") | size(WIDTH, EQUAL, 7) | bold,
        separator(),
        text("Latency") | size(WIDTH, EQUAL, 8) | bold,
    }));
    table_rows.push_back(separatorLight());

    if (!cached_entries.empty()) {
      selected = std::clamp(selected, 0, static_cast<int>(cached_entries.size()) - 1);
    }

    int max_visible = 20;
    int max_start = std::max(0, static_cast<int>(cached_entries.size()) - max_visible);
    int start_idx = std::clamp(selected - max_visible / 2, 0, max_start);
    int end_idx = std::min(static_cast<int>(cached_entries.size()), start_idx + max_visible);
    for (int i = start_idx; i < end_idx; ++i) {
      const auto& e = cached_entries[i];
      bool is_selected = (i == selected);

      auto row = hbox({
          text(FormatTimestamp(e.timestamp)) | size(WIDTH, EQUAL, 12),
          separator(),
          text(e.protocol) | size(WIDTH, EQUAL, 6) | color(ProtocolColor(e.protocol)),
          separator(),
          text(e.method) | size(WIDTH, EQUAL, 7) | bold,
          separator(),
          text(e.url) | flex,
          separator(),
          text(e.status > 0 ? fmt::format("{}", e.status) : "") | size(WIDTH, EQUAL, 7) |
              color(StatusColor(e.status)),
          separator(),
          text(e.latency) | size(WIDTH, EQUAL, 8),
      });

      if (is_selected)
        row = row | inverted;
      table_rows.push_back(row);
    }

    Element request_list;
    if (endpoint_view) {
      std::vector<Element> endpoint_rows;
      endpoint_rows.push_back(hbox({
          text("Method") | size(WIDTH, EQUAL, 9) | bold,
          text("Normalized route") | flex | bold,
          text("Count") | size(WIDTH, EQUAL, 9) | bold,
          text("Errors") | size(WIDTH, EQUAL, 9) | bold,
          text("P95") | size(WIDTH, EQUAL, 10) | bold,
      }));
      endpoint_rows.push_back(separatorLight());
      for (const auto& endpoint : state_->GetEndpoints()) {
        endpoint_rows.push_back(hbox({
            text(endpoint.method) | size(WIDTH, EQUAL, 9),
            text(endpoint.route) | flex,
            text(fmt::format("{}", endpoint.count)) | size(WIDTH, EQUAL, 9),
            text(fmt::format("{}", endpoint.error_count)) | size(WIDTH, EQUAL, 9),
            text(fmt::format("{}ms", endpoint.p95_latency_us / 1000)) | size(WIDTH, EQUAL, 10),
        }));
      }
      request_list = vbox(std::move(endpoint_rows)) | borderLight | flex;
    } else {
      request_list = vbox(std::move(table_rows)) | borderLight | flex;
    }

    // ── Detail panel ──
    Element detail_panel = text("");
    if (show_detail && !cached_entries.empty() && selected >= 0 &&
        selected < static_cast<int>(cached_entries.size())) {
      const auto& e = cached_entries[selected];
      if (!e.detail.empty()) {
        std::vector<Element> detail_lines;
        std::string line;
        for (char c : e.detail) {
          if (c == '\n') {
            detail_lines.push_back(text(line));
            line.clear();
          } else {
            line += c;
          }
        }
        if (!line.empty())
          detail_lines.push_back(text(line));
        constexpr int kDetailLines = 12;
        detail_scroll = std::clamp(
            detail_scroll, 0, std::max(0, static_cast<int>(detail_lines.size()) - kDetailLines));
        std::vector<Element> visible_lines;
        auto begin = detail_lines.begin() + detail_scroll;
        auto end = detail_lines.begin() +
                   std::min(static_cast<int>(detail_lines.size()), detail_scroll + kDetailLines);
        visible_lines.insert(visible_lines.end(), std::make_move_iterator(begin),
                             std::make_move_iterator(end));
        detail_panel = vbox(std::move(visible_lines)) | borderLight | size(HEIGHT, LESS_THAN, 14);
      }
    }

    // ── Help bar ──
    auto help_bar = hbox({
                        text(" q") | bold | color(Color::Yellow),
                        text(":quit "),
                        text("↑↓") | bold | color(Color::Yellow),
                        text(":nav "),
                        text("d") | bold | color(Color::Yellow),
                        text(":detail "),
                        text("e") | bold | color(Color::Yellow),
                        text(endpoint_view ? ":requests " : ":endpoints "),
                        text("Space") | bold | color(Color::Yellow),
                        text(follow ? ":pause " : ":follow "),
                        text("PgUp/PgDn") | bold | color(Color::Yellow),
                        text(":detail scroll "),
                        text("/") | bold | color(Color::Yellow),
                        text(":filter "),
                        text("Esc") | bold | color(Color::Yellow),
                        text(":clear"),
                    }) |
                    dim;

    return vbox({
        stats_bar,
        filter_bar_el,
        request_list,
        detail_panel,
        help_bar,
    });
  });

  component = CatchEvent(component, [&](ftxui::Event event) -> bool {
    // Filter mode input.
    if (filter_active) {
      if (event == ftxui::Event::Escape) {
        filter_active = false;
        filter_text.clear();
        return true;
      }
      if (event == ftxui::Event::Return) {
        filter_active = false;
        return true;
      }
      if (event == ftxui::Event::Backspace) {
        if (!filter_text.empty())
          filter_text.pop_back();
        return true;
      }
      if (event.is_character()) {
        filter_text += event.character();
        return true;
      }
      return false;
    }

    // Normal mode.
    if (event == ftxui::Event::Character('q') || event == ftxui::Event::Escape) {
      running_ = false;
      source->Stop();
      screen.Exit();
      return true;
    }
    if (event == ftxui::Event::ArrowUp) {
      if (selected > 0) {
        --selected;
        follow = false;
        detail_scroll = 0;
      }
      return true;
    }
    if (event == ftxui::Event::ArrowDown) {
      if (selected < static_cast<int>(cached_entries.size()) - 1) {
        ++selected;
        follow = false;
        detail_scroll = 0;
      }
      return true;
    }
    if (event == ftxui::Event::Character(' ')) {
      follow = !follow;
      if (follow)
        selected = std::max(0, static_cast<int>(cached_entries.size()) - 1);
      return true;
    }
    if (event == ftxui::Event::PageUp) {
      detail_scroll = std::max(0, detail_scroll - 6);
      return true;
    }
    if (event == ftxui::Event::PageDown) {
      detail_scroll += 6;
      return true;
    }
    if (event == ftxui::Event::Character('d')) {
      show_detail = !show_detail;
      return true;
    }
    if (event == ftxui::Event::Character('e')) {
      endpoint_view = !endpoint_view;
      return true;
    }
    if (event == ftxui::Event::Character('/')) {
      filter_active = true;
      filter_text.clear();
      return true;
    }
    if (event == ftxui::Event::Custom) {
      if (follow && filter_text.empty()) {
        selected = std::max(0, static_cast<int>(cached_entries.size()) - 1);
        detail_scroll = 0;
      }
      return true;
    }
    return false;
  });

  auto loop = ftxui::Loop(&screen, component);
  while (running_ && !loop.HasQuitted()) {
    loop.RunOnce();
    screen.Post(ftxui::Event::Custom);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  running_ = false;
  source->Stop();
  if (capture_thread.joinable()) {
    capture_thread.join();
  }
}

}  // namespace wirepeek::tui
