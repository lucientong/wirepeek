// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file capture/file_source.h
/// @brief Packet capture from .pcap/.pcapng files.

#pragma once

#include <wirepeek/capture/capture.h>

#include <atomic>
#include <memory>
#include <string>

struct pcap;
typedef struct pcap pcap_t;

namespace wirepeek::capture {

/// Reads packets from a pcap capture file.
class FileSource : public CaptureSource {
 public:
  /// Open a pcap file for reading.
  /// @param file_path Path to the .pcap or .pcapng file.
  /// @throws std::runtime_error if the file cannot be opened.
  explicit FileSource(const std::string& file_path);

  ~FileSource() override;

  FileSource(const FileSource&) = delete;
  FileSource& operator=(const FileSource&) = delete;

  void Start(PacketCallback callback) override;
  void Stop() override;
  CaptureStats Stats() const override;

 private:
  struct PcapDeleter {
    void operator()(pcap_t* p) const;
  };

  std::string file_path_;
  std::unique_ptr<pcap_t, PcapDeleter> handle_;
  std::atomic<bool> running_{false};
  uint64_t packets_read_ = 0;
};

}  // namespace wirepeek::capture
