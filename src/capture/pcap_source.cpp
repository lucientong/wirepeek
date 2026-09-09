// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/capture/pcap_source.h>
#include <wirepeek/dissector/link.h>

#include <chrono>
#include <pcap/pcap.h>
#include <spdlog/spdlog.h>
#include <stdexcept>

namespace wirepeek::capture {

void PcapSource::PcapDeleter::operator()(pcap_t* p) const {
  if (p)
    pcap_close(p);
}

PcapSource::PcapSource(PcapConfig config) : config_(std::move(config)) {
  char errbuf[PCAP_ERRBUF_SIZE];

  // Create the pcap handle.
  pcap_t* raw = pcap_create(config_.interface.c_str(), errbuf);
  if (!raw) {
    throw std::runtime_error(
        fmt::format("Failed to create pcap handle for '{}': {}", config_.interface, errbuf));
  }
  handle_.reset(raw);

  // Configure capture parameters.
  pcap_set_snaplen(raw, config_.snaplen);
  pcap_set_promisc(raw, config_.promiscuous ? 1 : 0);
  pcap_set_timeout(raw, config_.timeout_ms);

  // Try to enable immediate mode for low-latency capture.
  pcap_set_immediate_mode(raw, 1);

  // Activate the handle.
  int status = pcap_activate(raw);
  if (status < 0) {
    throw std::runtime_error(fmt::format("Failed to activate pcap on '{}': {}", config_.interface,
                                         pcap_statustostr(status)));
  }
  if (status > 0) {
    spdlog::warn("pcap_activate warning on '{}': {}", config_.interface, pcap_statustostr(status));
  }

  link_type_ = dissector::MapPcapDatalink(pcap_datalink(raw));
  if (link_type_ == LinkType::kUnknown) {
    spdlog::warn("Unsupported datalink type {} on '{}'; packets may not dissect",
                 pcap_datalink(raw), config_.interface);
  }

  // Apply BPF filter if specified.
  if (!config_.bpf_filter.empty()) {
    struct bpf_program fp;
    if (pcap_compile(raw, &fp, config_.bpf_filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
      throw std::runtime_error(fmt::format("Failed to compile BPF filter '{}': {}",
                                           config_.bpf_filter, pcap_geterr(raw)));
    }
    if (pcap_setfilter(raw, &fp) < 0) {
      pcap_freecode(&fp);
      throw std::runtime_error(fmt::format("Failed to set BPF filter: {}", pcap_geterr(raw)));
    }
    pcap_freecode(&fp);
  }

  spdlog::info("Opened capture on interface '{}' (snaplen={}, filter='{}', link={})",
               config_.interface, config_.snaplen, config_.bpf_filter,
               static_cast<uint32_t>(link_type_));
}

PcapSource::~PcapSource() {
  Stop();
}

void PcapSource::Start(PacketCallback callback) {
  running_ = true;

  struct CallbackContext {
    PacketCallback* cb;
    std::atomic<bool>* running;
    LinkType link_type;
  };

  CallbackContext ctx{&callback, &running_, link_type_};

  auto pcap_handler = [](u_char* user, const struct pcap_pkthdr* hdr, const u_char* bytes) {
    auto* ctx = reinterpret_cast<CallbackContext*>(user);
    if (!ctx->running->load(std::memory_order_relaxed))
      return;

    auto ts = std::chrono::time_point_cast<std::chrono::microseconds>(
        std::chrono::system_clock::time_point(std::chrono::seconds(hdr->ts.tv_sec) +
                                              std::chrono::microseconds(hdr->ts.tv_usec)));

    PacketView view{
        .data = std::span<const uint8_t>(bytes, hdr->caplen),
        .timestamp = ts,
        .capture_length = hdr->caplen,
        .original_length = hdr->len,
        .link_type = ctx->link_type,
    };

    (*ctx->cb)(view);
  };

  int result = pcap_loop(handle_.get(), -1, pcap_handler, reinterpret_cast<u_char*>(&ctx));

  if (result == PCAP_ERROR && running_) {
    spdlog::error("pcap_loop error: {}", pcap_geterr(handle_.get()));
  }

  running_ = false;
}

void PcapSource::Stop() {
  if (running_.exchange(false) && handle_) {
    pcap_breakloop(handle_.get());
  }
}

CaptureStats PcapSource::Stats() const {
  CaptureStats stats;
  if (handle_) {
    struct pcap_stat ps;
    if (pcap_stats(handle_.get(), &ps) == 0) {
      stats.packets_received = ps.ps_recv;
      stats.packets_dropped = ps.ps_drop;
#ifdef __linux__
      stats.packets_if_dropped = ps.ps_ifdrop;
#endif
    }
  }
  return stats;
}

}  // namespace wirepeek::capture
