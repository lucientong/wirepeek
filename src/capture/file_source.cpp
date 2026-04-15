// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/capture/file_source.h>

#include <chrono>
#include <pcap/pcap.h>
#include <spdlog/spdlog.h>
#include <stdexcept>

namespace wirepeek::capture {

void FileSource::PcapDeleter::operator()(pcap_t* p) const {
  if (p)
    pcap_close(p);
}

FileSource::FileSource(const std::string& file_path) : file_path_(file_path) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* raw = pcap_open_offline(file_path.c_str(), errbuf);
  if (!raw) {
    throw std::runtime_error(fmt::format("Failed to open pcap file '{}': {}", file_path, errbuf));
  }
  handle_.reset(raw);
  spdlog::info("Opened pcap file '{}'", file_path);
}

FileSource::~FileSource() {
  Stop();
}

void FileSource::Start(PacketCallback callback) {
  running_ = true;
  packets_read_ = 0;

  struct pcap_pkthdr* hdr;
  const u_char* bytes;

  while (running_) {
    int result = pcap_next_ex(handle_.get(), &hdr, &bytes);
    if (result == 1) {
      // Packet read successfully.
      auto ts = std::chrono::time_point_cast<std::chrono::microseconds>(
          std::chrono::system_clock::time_point(std::chrono::seconds(hdr->ts.tv_sec) +
                                                std::chrono::microseconds(hdr->ts.tv_usec)));

      PacketView view{
          .data = std::span<const uint8_t>(bytes, hdr->caplen),
          .timestamp = ts,
          .capture_length = hdr->caplen,
          .original_length = hdr->len,
      };

      callback(view);
      ++packets_read_;
    } else if (result == PCAP_ERROR_BREAK || result == -2) {
      // End of file.
      break;
    } else if (result == PCAP_ERROR) {
      spdlog::error("Error reading pcap file: {}", pcap_geterr(handle_.get()));
      break;
    }
    // result == 0: timeout (shouldn't happen for files, but continue).
  }

  running_ = false;
  spdlog::info("Finished reading '{}': {} packets", file_path_, packets_read_);
}

void FileSource::Stop() {
  running_ = false;
}

CaptureStats FileSource::Stats() const {
  return CaptureStats{
      .packets_received = packets_read_,
      .packets_dropped = 0,
      .packets_if_dropped = 0,
  };
}

}  // namespace wirepeek::capture
