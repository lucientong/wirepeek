// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file export/pcap_writer.h
/// @brief Export captured packets to .pcap format.

#pragma once

#include <wirepeek/packet.h>

#include <cstdint>
#include <string>
#include <vector>

namespace wirepeek::exporter {

/// Writes packets to a pcap file (libpcap format).
class PcapWriter {
 public:
  /// Open a new pcap file for writing.
  /// @throws std::runtime_error if file cannot be opened.
  explicit PcapWriter(const std::string& path);
  ~PcapWriter();

  PcapWriter(const PcapWriter&) = delete;
  PcapWriter& operator=(const PcapWriter&) = delete;

  /// Write a packet to the file.
  void WritePacket(const PacketView& pkt);

  /// Number of packets written.
  [[nodiscard]] uint64_t PacketCount() const { return count_; }

  /// Close the file (also called by destructor).
  void Close();

 private:
  void WriteFileHeader();

  std::string path_;
  int fd_ = -1;
  uint64_t count_ = 0;
};

}  // namespace wirepeek::exporter
