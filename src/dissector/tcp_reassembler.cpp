// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/dissector/ip.h>
#include <wirepeek/dissector/tcp.h>
#include <wirepeek/dissector/tcp_reassembler.h>

#include <algorithm>
#include <spdlog/spdlog.h>
#include <variant>

namespace wirepeek::dissector {

TcpReassembler::TcpReassembler(StreamCallback callback, ReassemblerConfig config)
    : callback_(std::move(callback)), config_(config) {}

ConnectionKey TcpReassembler::MakeStreamKey(const DissectedPacket& packet) {
  ConnectionKey key;
  if (!packet.ip || !packet.tcp)
    return key;

  const auto& ip = *packet.ip;
  const auto& tcp = *packet.tcp;

  // Normalize: lower IP:port pair always goes in src to ensure
  // both directions of the same connection map to the same key.
  bool swap = false;
  if (tcp.src_port > tcp.dst_port) {
    swap = true;
  } else if (tcp.src_port == tcp.dst_port) {
    // Compare IP addresses lexicographically.
    if (const auto* v4_src = std::get_if<Ipv4Address>(&ip.src_ip)) {
      const auto* v4_dst = std::get_if<Ipv4Address>(&ip.dst_ip);
      if (v4_dst && *v4_src > *v4_dst)
        swap = true;
    } else if (const auto* v6_src = std::get_if<Ipv6Address>(&ip.src_ip)) {
      const auto* v6_dst = std::get_if<Ipv6Address>(&ip.dst_ip);
      if (v6_dst && *v6_src > *v6_dst)
        swap = true;
    }
  }

  auto copy_ip = [](const IpAddress& addr, std::array<uint8_t, 16>& out) {
    out.fill(0);
    if (const auto* v4 = std::get_if<Ipv4Address>(&addr)) {
      std::copy(v4->begin(), v4->end(), out.begin());
    } else {
      const auto& v6 = std::get<Ipv6Address>(addr);
      std::copy(v6.begin(), v6.end(), out.begin());
    }
  };

  if (swap) {
    copy_ip(ip.dst_ip, key.src_ip);
    copy_ip(ip.src_ip, key.dst_ip);
    key.src_port = tcp.dst_port;
    key.dst_port = tcp.src_port;
  } else {
    copy_ip(ip.src_ip, key.src_ip);
    copy_ip(ip.dst_ip, key.dst_ip);
    key.src_port = tcp.src_port;
    key.dst_port = tcp.dst_port;
  }
  key.ip_version = ip.version;
  key.protocol = ip.protocol;
  return key;
}

TcpStream* TcpReassembler::GetOrCreateStream(const DissectedPacket& packet, Timestamp ts) {
  auto key = MakeStreamKey(packet);
  auto it = streams_.find(key);
  if (it != streams_.end()) {
    it->second.last_activity = ts;
    return &it->second;
  }

  // Check limits.
  if (streams_.size() >= config_.max_streams) {
    // Evict the oldest stream.
    auto oldest = streams_.begin();
    for (auto sit = streams_.begin(); sit != streams_.end(); ++sit) {
      if (sit->second.last_activity < oldest->second.last_activity) {
        oldest = sit;
      }
    }
    Emit(oldest->second, 0, StreamEventType::kClose);
    streams_.erase(oldest);
  }

  auto [new_it, _] = streams_.emplace(key, TcpStream{});
  auto& stream = new_it->second;
  stream.key = key;
  stream.last_activity = ts;
  return &stream;
}

int TcpReassembler::GetDirection(const TcpStream& stream, const DissectedPacket& packet) const {
  if (!packet.ip || !packet.tcp)
    return 0;
  const auto& tcp = *packet.tcp;

  // Determine if this packet's src maps to key.src (halves[0]) or key.dst (halves[1]).
  // This uses the same normalization logic as MakeStreamKey.
  bool packet_is_key_src = true;
  if (tcp.src_port == tcp.dst_port) {
    if (const auto* v4_src = std::get_if<Ipv4Address>(&packet.ip->src_ip)) {
      const auto* v4_dst = std::get_if<Ipv4Address>(&packet.ip->dst_ip);
      if (v4_dst && *v4_src > *v4_dst)
        packet_is_key_src = false;
    } else if (const auto* v6_src = std::get_if<Ipv6Address>(&packet.ip->src_ip)) {
      const auto* v6_dst = std::get_if<Ipv6Address>(&packet.ip->dst_ip);
      if (v6_dst && *v6_src > *v6_dst)
        packet_is_key_src = false;
    }
  } else {
    packet_is_key_src = (tcp.src_port < tcp.dst_port);
  }

  // halves[0] = traffic from key.src, halves[1] = traffic from key.dst.
  return packet_is_key_src ? 0 : 1;
}

void TcpReassembler::HandleSyn(TcpStream& stream, const DissectedPacket& packet, int dir) {
  const auto& tcp = *packet.tcp;

  if (tcp.flags & tcp_flags::kSYN) {
    bool is_syn_ack = (tcp.flags & tcp_flags::kACK) != 0;

    if (!is_syn_ack && stream.state == TcpStreamState::kNew) {
      // Pure SYN: this is the client. `dir` tells us which halves[] index this maps to.
      stream.state = TcpStreamState::kSynSent;
      stream.client_is_src = (dir == 0);  // client maps to key.src if dir==0

      // Initialize client half-stream sequence.
      stream.halves[dir].initial_seq = tcp.seq_num;
      stream.halves[dir].next_expected_seq = tcp.seq_num + 1;  // SYN consumes 1 seq.
      stream.halves[dir].seq_initialized = true;

      Emit(stream, dir, StreamEventType::kOpen);
    } else if (is_syn_ack) {
      // SYN-ACK: this is the server responding.
      stream.state = TcpStreamState::kEstablished;

      stream.halves[dir].initial_seq = tcp.seq_num;
      stream.halves[dir].next_expected_seq = tcp.seq_num + 1;
      stream.halves[dir].seq_initialized = true;
    }
  }
}

void TcpReassembler::HandleData(TcpStream& stream, int dir, uint32_t seq,
                                std::span<const uint8_t> payload) {
  if (payload.empty())
    return;

  auto& half = stream.halves[dir];

  // Check per-stream memory limit.
  if (half.total_bytes + payload.size() > config_.max_bytes_per_stream) {
    spdlog::debug("Stream memory limit exceeded, dropping segment");
    return;
  }

  // Initialize sequence if not yet set (mid-flow join).
  if (!half.seq_initialized) {
    half.initial_seq = seq;
    half.next_expected_seq = seq;
    half.seq_initialized = true;

    if (stream.state == TcpStreamState::kNew) {
      // Joined mid-flow. Use port heuristic: lower port = server.
      stream.state = TcpStreamState::kEstablished;
      Emit(stream, dir, StreamEventType::kOpen);
    }
  }

  if (seq == half.next_expected_seq) {
    // In-order: emit immediately.
    half.next_expected_seq = seq + static_cast<uint32_t>(payload.size());
    half.total_bytes += payload.size();
    Emit(stream, dir, StreamEventType::kData, payload);

    // Flush any buffered segments that are now contiguous.
    FlushBuffered(stream, dir);
  } else if (SeqBefore(half.next_expected_seq, seq)) {
    // Out-of-order: buffer for later.
    half.out_of_order.emplace(seq, std::vector<uint8_t>(payload.begin(), payload.end()));
  }
  // else: seq < next_expected → retransmission, ignore.
}

void TcpReassembler::FlushBuffered(TcpStream& stream, int dir) {
  auto& half = stream.halves[dir];
  while (!half.out_of_order.empty()) {
    auto it = half.out_of_order.begin();
    if (SeqBefore(it->first, half.next_expected_seq)) {
      // Already received, discard.
      half.out_of_order.erase(it);
      continue;
    }
    if (it->first != half.next_expected_seq) {
      break;  // Gap remains.
    }
    // Contiguous: emit.
    half.next_expected_seq = it->first + static_cast<uint32_t>(it->second.size());
    half.total_bytes += it->second.size();
    Emit(stream, dir, StreamEventType::kData, it->second);
    half.out_of_order.erase(it);
  }
}

void TcpReassembler::HandleClose(TcpStream& stream, const DissectedPacket& packet, int dir) {
  const auto& tcp = *packet.tcp;

  if (tcp.flags & tcp_flags::kRST) {
    stream.state = TcpStreamState::kClosed;
    Emit(stream, dir, StreamEventType::kClose);
    return;
  }

  if (tcp.flags & tcp_flags::kFIN) {
    stream.halves[dir].fin_seen = true;

    if (stream.state == TcpStreamState::kEstablished || stream.state == TcpStreamState::kNew) {
      stream.state = TcpStreamState::kClosing;
    }

    // Both sides FIN'd → fully closed.
    if (stream.halves[0].fin_seen && stream.halves[1].fin_seen) {
      stream.state = TcpStreamState::kClosed;
      Emit(stream, dir, StreamEventType::kClose);
    }
  }
}

void TcpReassembler::Emit(const TcpStream& stream, int dir, StreamEventType type,
                          std::span<const uint8_t> data) {
  if (!callback_)
    return;

  // Direction mapping: the "client" half-stream index depends on client_is_src.
  // client_is_src=true  → client is halves[0], server is halves[1]
  // client_is_src=false → client is halves[1], server is halves[0]
  int client_dir = stream.client_is_src ? 0 : 1;
  auto direction =
      (dir == client_dir) ? StreamDirection::kClientToServer : StreamDirection::kServerToClient;
  StreamEvent event{
      .key = stream.key,
      .direction = direction,
      .type = type,
      .data = data,
  };
  callback_(event);
}

void TcpReassembler::ProcessPacket(const DissectedPacket& packet, Timestamp ts) {
  // Only process TCP packets.
  if (!packet.ip || !packet.tcp)
    return;

  auto* stream = GetOrCreateStream(packet, ts);
  if (!stream)
    return;

  const auto& tcp = *packet.tcp;
  int dir = GetDirection(*stream, packet);

  // Handle SYN/SYN-ACK.
  if (tcp.flags & tcp_flags::kSYN) {
    HandleSyn(*stream, packet, dir);
  }

  // Handle data.
  if (!tcp.payload.empty()) {
    HandleData(*stream, dir, tcp.seq_num, tcp.payload);
  }

  // Handle FIN/RST.
  if (tcp.flags & (tcp_flags::kFIN | tcp_flags::kRST)) {
    HandleClose(*stream, packet, dir);

    // Remove closed streams.
    if (stream->state == TcpStreamState::kClosed) {
      streams_.erase(stream->key);
    }
  }
}

void TcpReassembler::FlushExpired(Timestamp now) {
  auto timeout = config_.idle_timeout;
  auto it = streams_.begin();
  while (it != streams_.end()) {
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_activity);
    if (elapsed >= timeout) {
      Emit(it->second, 0, StreamEventType::kClose);
      it = streams_.erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace wirepeek::dissector
