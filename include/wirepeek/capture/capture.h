// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file capture/capture.h
/// @brief Abstract base class for packet capture sources.

#pragma once

#include <wirepeek/packet.h>

#include <cstdint>
#include <functional>
#include <string>

namespace wirepeek::capture {

/// Callback invoked for each captured packet.
using PacketCallback = std::function<void(const PacketView&)>;

/// Capture statistics.
struct CaptureStats {
  uint64_t packets_received = 0;    ///< Packets received by the filter.
  uint64_t packets_dropped = 0;     ///< Packets dropped by the kernel.
  uint64_t packets_if_dropped = 0;  ///< Packets dropped by the network interface.
};

/// Abstract base class for packet capture sources.
///
/// Subclasses implement live capture (PcapSource) or file reading (FileSource).
class CaptureSource {
 public:
  virtual ~CaptureSource() = default;

  /// Start capturing packets. Blocks until Stop() is called or EOF is reached.
  /// @param callback Called for each captured packet.
  virtual void Start(PacketCallback callback) = 0;

  /// Request the capture to stop. May be called from a signal handler.
  virtual void Stop() = 0;

  /// Get capture statistics.
  virtual CaptureStats Stats() const = 0;
};

}  // namespace wirepeek::capture
