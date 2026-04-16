// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/export/pcap_writer.h>

#include <chrono>
#include <fcntl.h>
#include <stdexcept>
#include <unistd.h>

namespace wirepeek::exporter {

namespace {
// pcap file header (24 bytes).
struct PcapFileHeader {
  uint32_t magic = 0xA1B2C3D4;
  uint16_t version_major = 2;
  uint16_t version_minor = 4;
  int32_t thiszone = 0;
  uint32_t sigfigs = 0;
  uint32_t snaplen = 65535;
  uint32_t linktype = 1;  // LINKTYPE_ETHERNET
};

// pcap packet header (16 bytes).
struct PcapPacketHeader {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t caplen;
  uint32_t origlen;
};
}  // namespace

PcapWriter::PcapWriter(const std::string& path) : path_(path) {
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
  ::write(fd_, &hdr, sizeof(hdr));
}

void PcapWriter::WritePacket(const PacketView& pkt) {
  if (fd_ < 0)
    return;

  auto epoch = pkt.timestamp.time_since_epoch();
  auto secs = std::chrono::duration_cast<std::chrono::seconds>(epoch);
  auto usecs = std::chrono::duration_cast<std::chrono::microseconds>(epoch) -
               std::chrono::duration_cast<std::chrono::microseconds>(secs);

  PcapPacketHeader phdr;
  phdr.ts_sec = static_cast<uint32_t>(secs.count());
  phdr.ts_usec = static_cast<uint32_t>(usecs.count());
  phdr.caplen = static_cast<uint32_t>(pkt.data.size());
  phdr.origlen = pkt.original_length > 0 ? pkt.original_length : phdr.caplen;

  ::write(fd_, &phdr, sizeof(phdr));
  ::write(fd_, pkt.data.data(), pkt.data.size());
  ++count_;
}

void PcapWriter::Close() {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

}  // namespace wirepeek::exporter
