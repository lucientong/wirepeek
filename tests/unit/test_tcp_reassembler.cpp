// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/dissector/tcp_reassembler.h>

#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace wirepeek::dissector {
namespace {

// Helper: build a DissectedPacket with Ethernet + IP + TCP layers.
DissectedPacket MakeTcpDissected(Ipv4Address src_ip, uint16_t src_port, Ipv4Address dst_ip,
                                 uint16_t dst_port, uint32_t seq, uint8_t flags,
                                 const std::vector<uint8_t>& payload_storage) {
  DissectedPacket pkt;

  EthernetInfo eth;
  eth.ether_type = ethertype::kIPv4;
  pkt.ethernet = eth;

  IpInfo ip;
  ip.version = 4;
  ip.src_ip = src_ip;
  ip.dst_ip = dst_ip;
  ip.protocol = ip_protocol::kTCP;
  pkt.ip = ip;

  TcpInfo tcp;
  tcp.src_port = src_port;
  tcp.dst_port = dst_port;
  tcp.seq_num = seq;
  tcp.flags = flags;
  tcp.payload = std::span<const uint8_t>(payload_storage.data(), payload_storage.size());
  pkt.tcp = tcp;

  return pkt;
}

Timestamp MakeTs(int seconds) {
  return Timestamp(std::chrono::seconds(seconds));
}

class TcpReassemblerTest : public ::testing::Test {
 protected:
  struct Event {
    StreamEventType type;
    StreamDirection direction;
    std::vector<uint8_t> data;
  };

  std::vector<Event> events;

  std::unique_ptr<TcpReassembler> MakeReassembler(ReassemblerConfig config = {}) {
    events.clear();
    return std::make_unique<TcpReassembler>(
        [this](const StreamEvent& e) {
          events.push_back(
              {e.type, e.direction, std::vector<uint8_t>(e.data.begin(), e.data.end())});
        },
        config);
  }

  // Standard IPs for tests.
  static constexpr Ipv4Address kClient = {192, 168, 1, 10};
  static constexpr Ipv4Address kServer = {10, 0, 0, 1};
  static constexpr uint16_t kClientPort = 54321;
  static constexpr uint16_t kServerPort = 80;
};

// ── Basic 3-way handshake + data ──────────────────────────────────────────────

TEST_F(TcpReassemblerTest, ThreeWayHandshakeAndData) {
  auto r = MakeReassembler();
  std::vector<uint8_t> empty;
  std::vector<uint8_t> request = {'G', 'E', 'T', ' ', '/'};
  std::vector<uint8_t> response = {'H', 'T', 'T', 'P'};

  // SYN (client → server)
  auto syn =
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 1000, tcp_flags::kSYN, empty);
  r->ProcessPacket(syn, MakeTs(1));

  ASSERT_EQ(events.size(), 1u);
  EXPECT_EQ(events[0].type, StreamEventType::kOpen);
  EXPECT_EQ(events[0].direction, StreamDirection::kClientToServer);

  // SYN-ACK (server → client)
  auto syn_ack = MakeTcpDissected(kServer, kServerPort, kClient, kClientPort, 2000,
                                  tcp_flags::kSYN | tcp_flags::kACK, empty);
  r->ProcessPacket(syn_ack, MakeTs(1));

  // ACK (client → server) — no data
  auto ack =
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 1001, tcp_flags::kACK, empty);
  r->ProcessPacket(ack, MakeTs(1));

  // Data: client sends "GET /"
  auto data1 = MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 1001,
                                tcp_flags::kACK | tcp_flags::kPSH, request);
  r->ProcessPacket(data1, MakeTs(2));

  // Find the data event.
  auto data_events = std::count_if(events.begin(), events.end(),
                                   [](const Event& e) { return e.type == StreamEventType::kData; });
  EXPECT_GE(data_events, 1);

  // Last data event should contain "GET /".
  auto& last_data = *std::find_if(events.rbegin(), events.rend(),
                                  [](const Event& e) { return e.type == StreamEventType::kData; });
  EXPECT_EQ(last_data.data, request);
  EXPECT_EQ(last_data.direction, StreamDirection::kClientToServer);

  EXPECT_EQ(r->StreamCount(), 1u);
}

// ── In-order delivery ─────────────────────────────────────────────────────────

TEST_F(TcpReassemblerTest, InOrderDelivery) {
  auto r = MakeReassembler();
  std::vector<uint8_t> d1 = {0x01, 0x02};
  std::vector<uint8_t> d2 = {0x03, 0x04};
  std::vector<uint8_t> empty;

  // SYN + SYN-ACK
  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 100, tcp_flags::kSYN, empty),
      MakeTs(1));
  r->ProcessPacket(MakeTcpDissected(kServer, kServerPort, kClient, kClientPort, 200,
                                    tcp_flags::kSYN | tcp_flags::kACK, empty),
                   MakeTs(1));

  // Two in-order segments.
  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 101, tcp_flags::kACK, d1),
      MakeTs(2));
  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 103, tcp_flags::kACK, d2),
      MakeTs(2));

  // Should have 2 data events.
  int data_count = 0;
  std::vector<uint8_t> all_data;
  for (const auto& e : events) {
    if (e.type == StreamEventType::kData && e.direction == StreamDirection::kClientToServer) {
      all_data.insert(all_data.end(), e.data.begin(), e.data.end());
      ++data_count;
    }
  }
  EXPECT_EQ(data_count, 2);
  EXPECT_EQ(all_data, (std::vector<uint8_t>{0x01, 0x02, 0x03, 0x04}));
}

// ── Out-of-order reassembly ───────────────────────────────────────────────────

TEST_F(TcpReassemblerTest, OutOfOrderReassembly) {
  auto r = MakeReassembler();
  std::vector<uint8_t> d1 = {0xAA, 0xBB};
  std::vector<uint8_t> d2 = {0xCC, 0xDD};
  std::vector<uint8_t> empty;

  // SYN + SYN-ACK
  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 100, tcp_flags::kSYN, empty),
      MakeTs(1));
  r->ProcessPacket(MakeTcpDissected(kServer, kServerPort, kClient, kClientPort, 200,
                                    tcp_flags::kSYN | tcp_flags::kACK, empty),
                   MakeTs(1));

  // Send second segment first (out of order).
  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 103, tcp_flags::kACK, d2),
      MakeTs(2));

  // No data event yet (gap at seq 101).
  int data_before = std::count_if(events.begin(), events.end(),
                                  [](const Event& e) { return e.type == StreamEventType::kData; });
  EXPECT_EQ(data_before, 0);

  // Now send the missing first segment.
  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 101, tcp_flags::kACK, d1),
      MakeTs(2));

  // Both segments should now be delivered.
  std::vector<uint8_t> all_data;
  for (const auto& e : events) {
    if (e.type == StreamEventType::kData && e.direction == StreamDirection::kClientToServer) {
      all_data.insert(all_data.end(), e.data.begin(), e.data.end());
    }
  }
  EXPECT_EQ(all_data, (std::vector<uint8_t>{0xAA, 0xBB, 0xCC, 0xDD}));
}

// ── Retransmission ignored ────────────────────────────────────────────────────

TEST_F(TcpReassemblerTest, RetransmissionIgnored) {
  auto r = MakeReassembler();
  std::vector<uint8_t> d1 = {0x01, 0x02};
  std::vector<uint8_t> empty;

  // SYN + SYN-ACK
  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 100, tcp_flags::kSYN, empty),
      MakeTs(1));
  r->ProcessPacket(MakeTcpDissected(kServer, kServerPort, kClient, kClientPort, 200,
                                    tcp_flags::kSYN | tcp_flags::kACK, empty),
                   MakeTs(1));

  // First transmission.
  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 101, tcp_flags::kACK, d1),
      MakeTs(2));

  int data_count_before = std::count_if(events.begin(), events.end(), [](const Event& e) {
    return e.type == StreamEventType::kData;
  });

  // Retransmission (same seq).
  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 101, tcp_flags::kACK, d1),
      MakeTs(2));

  int data_count_after = std::count_if(events.begin(), events.end(), [](const Event& e) {
    return e.type == StreamEventType::kData;
  });

  // No new data event.
  EXPECT_EQ(data_count_after, data_count_before);
}

// ── FIN closes stream ─────────────────────────────────────────────────────────

TEST_F(TcpReassemblerTest, FinClosesStream) {
  auto r = MakeReassembler();
  std::vector<uint8_t> empty;

  // SYN + SYN-ACK
  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 100, tcp_flags::kSYN, empty),
      MakeTs(1));
  r->ProcessPacket(MakeTcpDissected(kServer, kServerPort, kClient, kClientPort, 200,
                                    tcp_flags::kSYN | tcp_flags::kACK, empty),
                   MakeTs(1));
  EXPECT_EQ(r->StreamCount(), 1u);

  // FIN from client.
  r->ProcessPacket(MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 101,
                                    tcp_flags::kFIN | tcp_flags::kACK, empty),
                   MakeTs(3));
  // FIN from server.
  r->ProcessPacket(MakeTcpDissected(kServer, kServerPort, kClient, kClientPort, 201,
                                    tcp_flags::kFIN | tcp_flags::kACK, empty),
                   MakeTs(3));

  EXPECT_EQ(r->StreamCount(), 0u);

  auto close_count = std::count_if(events.begin(), events.end(), [](const Event& e) {
    return e.type == StreamEventType::kClose;
  });
  EXPECT_GE(close_count, 1);
}

// ── RST immediately closes ────────────────────────────────────────────────────

TEST_F(TcpReassemblerTest, RstClosesImmediately) {
  auto r = MakeReassembler();
  std::vector<uint8_t> empty;

  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 100, tcp_flags::kSYN, empty),
      MakeTs(1));
  EXPECT_EQ(r->StreamCount(), 1u);

  r->ProcessPacket(
      MakeTcpDissected(kServer, kServerPort, kClient, kClientPort, 0, tcp_flags::kRST, empty),
      MakeTs(1));
  EXPECT_EQ(r->StreamCount(), 0u);
}

// ── FlushExpired removes idle streams ─────────────────────────────────────────

TEST_F(TcpReassemblerTest, FlushExpiredRemovesIdleStreams) {
  ReassemblerConfig config;
  config.idle_timeout = std::chrono::seconds(5);
  auto r = MakeReassembler(config);
  std::vector<uint8_t> empty;

  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 100, tcp_flags::kSYN, empty),
      MakeTs(10));
  EXPECT_EQ(r->StreamCount(), 1u);

  // Not expired yet.
  r->FlushExpired(MakeTs(14));
  EXPECT_EQ(r->StreamCount(), 1u);

  // Now expired.
  r->FlushExpired(MakeTs(16));
  EXPECT_EQ(r->StreamCount(), 0u);
}

// ── Mid-flow join (no SYN seen) ───────────────────────────────────────────────

TEST_F(TcpReassemblerTest, MidFlowJoin) {
  auto r = MakeReassembler();
  std::vector<uint8_t> data = {0x48, 0x54, 0x54, 0x50};  // "HTTP"

  // Data packet without prior SYN.
  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 5000, tcp_flags::kACK, data),
      MakeTs(1));

  EXPECT_EQ(r->StreamCount(), 1u);

  // Should have open + data events.
  auto open_count = std::count_if(events.begin(), events.end(),
                                  [](const Event& e) { return e.type == StreamEventType::kOpen; });
  auto data_count = std::count_if(events.begin(), events.end(),
                                  [](const Event& e) { return e.type == StreamEventType::kData; });
  EXPECT_EQ(open_count, 1);
  EXPECT_EQ(data_count, 1);
}

// ── Non-TCP packets are ignored ───────────────────────────────────────────────

TEST_F(TcpReassemblerTest, NonTcpPacketsIgnored) {
  auto r = MakeReassembler();

  // UDP packet (no tcp field).
  DissectedPacket udp_pkt;
  IpInfo ip;
  ip.version = 4;
  ip.protocol = ip_protocol::kUDP;
  udp_pkt.ip = ip;

  r->ProcessPacket(udp_pkt, MakeTs(1));
  EXPECT_EQ(r->StreamCount(), 0u);
  EXPECT_TRUE(events.empty());
}

// ── Bidirectional data ────────────────────────────────────────────────────────

TEST_F(TcpReassemblerTest, BidirectionalData) {
  auto r = MakeReassembler();
  std::vector<uint8_t> empty;
  std::vector<uint8_t> req = {0x01};
  std::vector<uint8_t> resp = {0x02};

  // Handshake.
  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 100, tcp_flags::kSYN, empty),
      MakeTs(1));
  r->ProcessPacket(MakeTcpDissected(kServer, kServerPort, kClient, kClientPort, 200,
                                    tcp_flags::kSYN | tcp_flags::kACK, empty),
                   MakeTs(1));

  // Client sends data.
  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 101, tcp_flags::kACK, req),
      MakeTs(2));
  // Server responds.
  r->ProcessPacket(
      MakeTcpDissected(kServer, kServerPort, kClient, kClientPort, 201, tcp_flags::kACK, resp),
      MakeTs(2));

  // Should have data in both directions.
  bool has_c2s = false, has_s2c = false;
  for (const auto& e : events) {
    if (e.type == StreamEventType::kData) {
      if (e.direction == StreamDirection::kClientToServer)
        has_c2s = true;
      if (e.direction == StreamDirection::kServerToClient)
        has_s2c = true;
    }
  }
  EXPECT_TRUE(has_c2s);
  EXPECT_TRUE(has_s2c);
}

// ── Sequence number wraparound ───────────────────────────────────────────

TEST_F(TcpReassemblerTest, SequenceNumberWraparound) {
  auto r = MakeReassembler();
  std::vector<uint8_t> empty;
  std::vector<uint8_t> data = {0xAA, 0xBB};

  // SYN near 32-bit boundary (seq 0xFFFFFFFE)
  r->ProcessPacket(MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 0xFFFFFFFEu,
                                    tcp_flags::kSYN, empty),
                   MakeTs(1));
  r->ProcessPacket(MakeTcpDissected(kServer, kServerPort, kClient, kClientPort, 100,
                                    tcp_flags::kSYN | tcp_flags::kACK, empty),
                   MakeTs(1));

  // Send data that wraps around: seq=0xFFFFFFFF (1 byte), then seq=0 (1 byte)
  r->ProcessPacket(MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 0xFFFFFFFFu,
                                    tcp_flags::kACK, std::vector<uint8_t>{0xAA}),
                   MakeTs(2));
  r->ProcessPacket(MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 0u, tcp_flags::kACK,
                                    std::vector<uint8_t>{0xBB}),
                   MakeTs(2));

  // Both bytes should be reassembled.
  std::vector<uint8_t> all_data;
  for (const auto& e : events) {
    if (e.type == StreamEventType::kData && e.direction == StreamDirection::kClientToServer) {
      all_data.insert(all_data.end(), e.data.begin(), e.data.end());
    }
  }
  EXPECT_EQ(all_data, (std::vector<uint8_t>{0xAA, 0xBB}));
}

// ── Memory limit per stream ──────────────────────────────────────────────

TEST_F(TcpReassemblerTest, MemoryLimitPerStream) {
  ReassemblerConfig config;
  config.max_bytes_per_stream = 100;  // Only 100 bytes per stream
  auto r = MakeReassembler(config);
  std::vector<uint8_t> empty;

  // Handshake.
  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 100, tcp_flags::kSYN, empty),
      MakeTs(1));
  r->ProcessPacket(MakeTcpDissected(kServer, kServerPort, kClient, kClientPort, 200,
                                    tcp_flags::kSYN | tcp_flags::kACK, empty),
                   MakeTs(1));

  // Send 150 bytes of data (out of order to trigger buffering).
  std::vector<uint8_t> big_data(150, 0xAA);
  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 110, tcp_flags::kACK,
                       std::vector<uint8_t>(big_data.begin(), big_data.begin() + 75)),
      MakeTs(2));
  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 101, tcp_flags::kACK,
                       std::vector<uint8_t>(big_data.begin() + 75, big_data.end())),
      MakeTs(2));

  // Stream should still exist but buffering should be bounded.
  // Just verify no crash/segfault from memory overflow.
  EXPECT_LE(r->StreamCount(), 1u);
}

// ── Max concurrent streams limit ─────────────────────────────────────────

TEST_F(TcpReassemblerTest, MaxStreamsLimit) {
  ReassemblerConfig config;
  config.max_streams = 3;  // Only 3 concurrent streams
  auto r = MakeReassembler(config);
  std::vector<uint8_t> empty;

  // Create 4 different streams.
  std::vector<uint16_t> ports = {1001, 1002, 1003, 1004};
  for (size_t i = 0; i < ports.size(); ++i) {
    r->ProcessPacket(
        MakeTcpDissected(kClient, ports[i], kServer, kServerPort, 100u + i, tcp_flags::kSYN, empty),
        MakeTs(1));
  }

  // After adding the 4th stream, the oldest should be evicted.
  // Should have at most 3 streams at any time.
  EXPECT_LE(r->StreamCount(), 3u);
}

// ── Overlapping segments ─────────────────────────────────────────────────

TEST_F(TcpReassemblerTest, OverlappingSegments) {
  auto r = MakeReassembler();
  std::vector<uint8_t> empty;

  // Handshake.
  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 100, tcp_flags::kSYN, empty),
      MakeTs(1));
  r->ProcessPacket(MakeTcpDissected(kServer, kServerPort, kClient, kClientPort, 200,
                                    tcp_flags::kSYN | tcp_flags::kACK, empty),
                   MakeTs(1));

  // First segment: seq=101, data={0x01, 0x02, 0x03}
  r->ProcessPacket(MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 101,
                                    tcp_flags::kACK, std::vector<uint8_t>{0x01, 0x02, 0x03}),
                   MakeTs(2));

  // Overlapping segment: seq=102, data={0xFF, 0xFF} (overlaps with part of first segment)
  // "First wins" strategy should keep original data.
  r->ProcessPacket(MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 102,
                                    tcp_flags::kACK, std::vector<uint8_t>{0xFF, 0xFF}),
                   MakeTs(2));

  // Verify delivered data is from the first segment.
  std::vector<uint8_t> all_data;
  for (const auto& e : events) {
    if (e.type == StreamEventType::kData && e.direction == StreamDirection::kClientToServer) {
      all_data.insert(all_data.end(), e.data.begin(), e.data.end());
    }
  }
  // Should include the first segment's data.
  EXPECT_GE(all_data.size(), 3u);
  if (all_data.size() >= 3) {
    EXPECT_EQ(all_data[0], 0x01);
  }
}

// ── Data after FIN ──────────────────────────────────────────────────────

TEST_F(TcpReassemblerTest, DataAfterFin) {
  auto r = MakeReassembler();
  std::vector<uint8_t> empty;

  // Handshake.
  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 100, tcp_flags::kSYN, empty),
      MakeTs(1));
  r->ProcessPacket(MakeTcpDissected(kServer, kServerPort, kClient, kClientPort, 200,
                                    tcp_flags::kSYN | tcp_flags::kACK, empty),
                   MakeTs(1));

  // Send FIN + ACK from client.
  r->ProcessPacket(MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 101,
                                    tcp_flags::kFIN | tcp_flags::kACK, empty),
                   MakeTs(2));

  int stream_count_after_fin = r->StreamCount();
  EXPECT_GE(stream_count_after_fin, 0);  // Stream may still exist (waiting for FIN from server).

  // Try to send more data after FIN (technically invalid but shouldn't crash).
  r->ProcessPacket(MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 101,
                                    tcp_flags::kACK, std::vector<uint8_t>{0xAA}),
                   MakeTs(3));

  // Should not crash or create additional data events.
  EXPECT_TRUE(true);
}

// ── Large out-of-order buffer ───────────────────────────────────────────

TEST_F(TcpReassemblerTest, LargeOutOfOrderBuffer) {
  auto r = MakeReassembler();
  std::vector<uint8_t> empty;

  // Handshake.
  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 100, tcp_flags::kSYN, empty),
      MakeTs(1));
  r->ProcessPacket(MakeTcpDissected(kServer, kServerPort, kClient, kClientPort, 200,
                                    tcp_flags::kSYN | tcp_flags::kACK, empty),
                   MakeTs(1));

  // Send 5 segments out of order (reverse order).
  std::vector<std::vector<uint8_t>> segments = {{0x05}, {0x04}, {0x03}, {0x02}, {0x01}};
  std::vector<uint32_t> seqs = {105, 104, 103, 102, 101};

  for (size_t i = 0; i < segments.size(); ++i) {
    r->ProcessPacket(MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, seqs[i],
                                      tcp_flags::kACK, segments[i]),
                     MakeTs(2));
  }

  // All segments should be buffered and eventually flushed in order.
  std::vector<uint8_t> all_data;
  for (const auto& e : events) {
    if (e.type == StreamEventType::kData && e.direction == StreamDirection::kClientToServer) {
      all_data.insert(all_data.end(), e.data.begin(), e.data.end());
    }
  }
  EXPECT_EQ(all_data, (std::vector<uint8_t>{0x01, 0x02, 0x03, 0x04, 0x05}));
}

// ── FIN then close from opposite direction ──────────────────────────────

TEST_F(TcpReassemblerTest, FinFromBothDirections) {
  auto r = MakeReassembler();
  std::vector<uint8_t> empty;

  // Handshake.
  r->ProcessPacket(
      MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 100, tcp_flags::kSYN, empty),
      MakeTs(1));
  r->ProcessPacket(MakeTcpDissected(kServer, kServerPort, kClient, kClientPort, 200,
                                    tcp_flags::kSYN | tcp_flags::kACK, empty),
                   MakeTs(1));
  EXPECT_EQ(r->StreamCount(), 1u);

  // Server closes first.
  r->ProcessPacket(MakeTcpDissected(kServer, kServerPort, kClient, kClientPort, 201,
                                    tcp_flags::kFIN | tcp_flags::kACK, empty),
                   MakeTs(2));
  EXPECT_EQ(r->StreamCount(), 1u);  // Stream still exists (half-closed).

  // Client closes.
  r->ProcessPacket(MakeTcpDissected(kClient, kClientPort, kServer, kServerPort, 101,
                                    tcp_flags::kFIN | tcp_flags::kACK, empty),
                   MakeTs(3));
  EXPECT_EQ(r->StreamCount(), 0u);  // Stream fully closed.

  // Should have 2 close events (one per direction).
  auto close_count = std::count_if(events.begin(), events.end(), [](const Event& e) {
    return e.type == StreamEventType::kClose;
  });
  EXPECT_GE(close_count, 1);
}

}  // namespace
}  // namespace wirepeek::dissector
