// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file capture/pcap_source.h
/// @brief Live packet capture using libpcap.

#pragma once

#include <wirepeek/capture/capture.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

// Forward-declare pcap types to avoid leaking pcap.h into headers.
struct pcap;
typedef struct pcap pcap_t;

namespace wirepeek::capture {

/// Configuration for live packet capture.
struct PcapConfig {
  std::string interface;            ///< Network interface name (e.g., "eth0", "lo0").
  std::string bpf_filter;          ///< BPF filter expression (e.g., "tcp port 80").
  int snaplen = 65535;             ///< Maximum bytes to capture per packet.
  int timeout_ms = 100;            ///< Read timeout in milliseconds.
  bool promiscuous = false;        ///< Enable promiscuous mode.
};

/// Live packet capture source using libpcap.
class PcapSource : public CaptureSource {
 public:
  /// Create a PcapSource with the given configuration.
  /// @throws std::runtime_error if the interface cannot be opened.
  explicit PcapSource(PcapConfig config);

  ~PcapSource() override;

  // Non-copyable, non-movable (owns a pcap handle).
  PcapSource(const PcapSource&) = delete;
  PcapSource& operator=(const PcapSource&) = delete;

  void Start(PacketCallback callback) override;
  void Stop() override;
  CaptureStats Stats() const override;

 private:
  /// Custom deleter for pcap_t*.
  struct PcapDeleter {
    void operator()(pcap_t* p) const;
  };

  PcapConfig config_;
  std::unique_ptr<pcap_t, PcapDeleter> handle_;
  std::atomic<bool> running_{false};
};

}  // namespace wirepeek::capture
