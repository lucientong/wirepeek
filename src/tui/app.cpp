// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/analyzer/statistics.h>
#include <wirepeek/dissector/dissect.h>
#include <wirepeek/dissector/tcp_reassembler.h>
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
#include <spdlog/spdlog.h>
#include <thread>
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

  auto protocol_handler = std::make_unique<protocol::ProtocolHandler>(
      [this, stats](const ConnectionKey& /*key*/, const HttpTransaction& txn) {
        state_->IncrementHttpTransactions();
        stats->RecordHttpTransaction(txn);

        TuiEntry entry;
        entry.timestamp = txn.request.timestamp;
        entry.protocol = "HTTP";
        entry.method = txn.request.method;
        entry.url = txn.request.url;
        entry.status = txn.response.status_code;

        if (txn.complete) {
          auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(txn.latency).count();
          entry.latency = fmt::format("{}ms", ms);
          entry.size = fmt::format("{}", txn.response.body_size);

          std::string detail;
          detail +=
              fmt::format("{} {} {}\n", txn.request.method, txn.request.url, txn.request.version);
          for (const auto& [name, value] : txn.request.headers) {
            detail += fmt::format("{}: {}\n", name, value);
          }
          detail += fmt::format("\n-> {} {} (Content-Length: {})\n", txn.response.status_code,
                                txn.response.reason, txn.response.body_size);
          for (const auto& [name, value] : txn.response.headers) {
            detail += fmt::format("{}: {}\n", name, value);
          }
          entry.detail = std::move(detail);
        } else {
          entry.detail = fmt::format("{} {} {}\n(no response)\n", txn.request.method,
                                     txn.request.url, txn.request.version);
        }

        state_->AddEntry(std::move(entry));
      },
      [this](const ConnectionKey& /*key*/, StreamDirection dir, std::span<const uint8_t> data) {
        TuiEntry entry;
        entry.timestamp = std::chrono::time_point_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now());
        entry.protocol = "TCP";
        entry.url = (dir == StreamDirection::kClientToServer) ? "client->server" : "server->client";
        entry.size = fmt::format("{}", data.size());
        entry.detail = fmt::format("Raw TCP data: {} bytes\n", data.size());
        state_->AddEntry(std::move(entry));
      });

  std::unique_ptr<dissector::TcpReassembler> reassembler;
  if (!config_.no_reassemble) {
    reassembler = std::make_unique<dissector::TcpReassembler>(
        [&protocol_handler](const dissector::StreamEvent& event) {
          auto now = std::chrono::time_point_cast<std::chrono::microseconds>(
              std::chrono::system_clock::now());
          protocol_handler->OnStreamEvent(event, now);
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
    }

    auto dissected = dissector::Dissect(pkt);

    if (reassembler) {
      reassembler->ProcessPacket(dissected, pkt.timestamp);
      state_->SetStreamCount(reassembler->StreamCount());
    }

    if (!dissected.tcp && dissected.ip) {
      TuiEntry entry;
      entry.timestamp = pkt.timestamp;
      if (dissected.udp) {
        entry.protocol = "UDP";
        entry.url = fmt::format("port {} -> {}", dissected.udp->src_port, dissected.udp->dst_port);
        entry.size = fmt::format("{}", dissected.udp->payload.size());
      } else {
        entry.protocol = fmt::format("proto={}", dissected.ip->protocol);
        entry.url = dissector::FormatSummary(dissected);
      }
      state_->AddEntry(std::move(entry));
    }

    auto snap = stats->Snapshot();
    state_->UpdateAnalyzerStats(snap.p50_latency_us, snap.p95_latency_us, snap.p99_latency_us,
                                snap.throughput_mbps, snap.qps);
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
  bool filter_active = false;
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
    int start_idx = std::max(0, static_cast<int>(cached_entries.size()) - max_visible);
    for (int i = start_idx; i < static_cast<int>(cached_entries.size()); ++i) {
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

    auto request_list = vbox(std::move(table_rows)) | borderLight | flex;

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
        detail_panel = vbox(std::move(detail_lines)) | borderLight | size(HEIGHT, LESS_THAN, 10);
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
      if (selected > 0)
        --selected;
      return true;
    }
    if (event == ftxui::Event::ArrowDown) {
      if (selected < static_cast<int>(cached_entries.size()) - 1)
        ++selected;
      return true;
    }
    if (event == ftxui::Event::Character('d')) {
      show_detail = !show_detail;
      return true;
    }
    if (event == ftxui::Event::Character('/')) {
      filter_active = true;
      filter_text.clear();
      return true;
    }
    if (event == ftxui::Event::Custom) {
      if (filter_text.empty()) {
        selected = std::max(0, static_cast<int>(cached_entries.size()) - 1);
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
