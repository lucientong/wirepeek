// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/export/pcap_writer.h>

#include <chrono>
#include <fcntl.h>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <unistd.h>

namespace wirepeek::exporter {

namespace {
struct PcapFileHeader {
  uint32_t magic = 0xA1B2C3D4;
  uint16_t version_major = 2;
  uint16_t version_minor = 4;
  int32_t thiszone = 0;
  uint32_t sigfigs = 0;
  uint32_t snaplen = 65535;
  uint32_t linktype = 1;
};

struct PcapPacketHeader {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t caplen;
  uint32_t origlen;
};

ssize_t WriteAll(int fd, const void* data, size_t len) {
  const auto* p = static_cast<const uint8_t*>(data);
  size_t written = 0;
  while (written < len) {
    const ssize_t n = ::write(fd, p + written, len - written);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return n;
    }
    if (n == 0)
      break;
    written += static_cast<size_t>(n);
  }
  return static_cast<ssize_t>(written);
}
}  // namespace

PcapWriter::PcapWriter(const std::string& path, LinkType link_type)
    : path_(path), link_type_(link_type) {
  if (link_type_ == LinkType::kUnknown) {
    throw std::runtime_error("Cannot write pcap with unknown link type");
  }
  fd_ = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd_ < 0) {
    throw std::runtime_error("Failed to open pcap file: " + path);
  }
  WriteFileHeader();
}

PcapWriter::~PcapWriter() {
  Close();
}

void PcapWriter::WriteFileHeader() {
  PcapFileHeader hdr;
  hdr.linktype = static_cast<uint32_t>(link_type_);
  if (WriteAll(fd_, &hdr, sizeof(hdr)) != static_cast<ssize_t>(sizeof(hdr))) {
    throw std::runtime_error("Failed to write pcap file header");
  }
}

void PcapWriter::WritePacket(const PacketView& pkt) {
  if (fd_ < 0)
    return;
  if (pkt.link_type != link_type_) {
    spdlog::warn("Skipping packet with mismatched link type");
    return;
  }

  auto epoch = pkt.timestamp.time_since_epoch();
  auto secs = std::chrono::duration_cast<std::chrono::seconds>(epoch);
  auto usecs = std::chrono::duration_cast<std::chrono::microseconds>(epoch) -
               std::chrono::duration_cast<std::chrono::microseconds>(secs);

  PcapPacketHeader phdr;
  phdr.ts_sec = static_cast<uint32_t>(secs.count());
  phdr.ts_usec = static_cast<uint32_t>(usecs.count());
  phdr.caplen = static_cast<uint32_t>(pkt.data.size());
  phdr.origlen = pkt.original_length > 0 ? pkt.original_length : phdr.caplen;

  if (WriteAll(fd_, &phdr, sizeof(phdr)) != static_cast<ssize_t>(sizeof(phdr)) ||
      WriteAll(fd_, pkt.data.data(), pkt.data.size()) != static_cast<ssize_t>(pkt.data.size())) {
    spdlog::error("Failed to write pcap packet");
    return;
  }
  ++count_;
}

void PcapWriter::Close() {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

}  // namespace wirepeek::exporter
