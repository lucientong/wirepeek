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

  bool swap = false;
  if (tcp.src_port > tcp.dst_port) {
    swap = true;
  } else if (tcp.src_port == tcp.dst_port) {
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

void TcpReassembler::TouchLru(TcpStream& stream) {
  if (stream.in_lru) {
    lru_.erase(stream.lru_it);
  }
  lru_.push_front(stream.key);
  stream.lru_it = lru_.begin();
  stream.in_lru = true;
}

TcpStream* TcpReassembler::GetOrCreateStream(const DissectedPacket& packet, Timestamp ts) {
  auto key = MakeStreamKey(packet);
  auto it = streams_.find(key);
  if (it != streams_.end()) {
    it->second.last_activity = ts;
    TouchLru(it->second);
    return &it->second;
  }

  while (streams_.size() >= config_.max_streams && !lru_.empty()) {
    const ConnectionKey victim = lru_.back();
    CloseAndErase(victim, 0, ts);
  }

  auto [new_it, _] = streams_.emplace(key, TcpStream{});
  auto& stream = new_it->second;
  stream.key = key;
  stream.last_activity = ts;
  TouchLru(stream);
  return &stream;
}

int TcpReassembler::GetDirection(const TcpStream& stream, const DissectedPacket& packet) const {
  (void)stream;
  if (!packet.ip || !packet.tcp)
    return 0;
  const auto& tcp = *packet.tcp;

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

  return packet_is_key_src ? 0 : 1;
}

void TcpReassembler::HandleSyn(TcpStream& stream, const DissectedPacket& packet, int dir,
                               Timestamp ts) {
  const auto& tcp = *packet.tcp;

  if (tcp.flags & tcp_flags::kSYN) {
    bool is_syn_ack = (tcp.flags & tcp_flags::kACK) != 0;

    if (!is_syn_ack && stream.state == TcpStreamState::kNew) {
      stream.state = TcpStreamState::kSynSent;
      stream.syn_timestamp = ts;
      stream.client_is_src = (dir == 0);
      stream.halves[dir].initial_seq = tcp.seq_num;
      stream.halves[dir].next_expected_seq = tcp.seq_num + 1;
      stream.halves[dir].seq_initialized = true;
      Emit(stream, dir, StreamEventType::kOpen, {}, ts);
    } else if (is_syn_ack) {
      stream.state = TcpStreamState::kEstablished;
      if (stream.syn_timestamp)
        stream.tcp_handshake = std::chrono::duration_cast<std::chrono::microseconds>(
            ts - *stream.syn_timestamp);
      stream.halves[dir].initial_seq = tcp.seq_num;
      stream.halves[dir].next_expected_seq = tcp.seq_num + 1;
      stream.halves[dir].seq_initialized = true;
    }
  }
}

void TcpReassembler::HandleData(TcpStream& stream, int dir, uint32_t seq,
                                std::span<const uint8_t> payload, Timestamp ts) {
  if (payload.empty())
    return;

  auto& half = stream.halves[dir];

  if (!half.seq_initialized) {
    half.initial_seq = seq;
    half.next_expected_seq = seq;
    half.seq_initialized = true;
    if (stream.state == TcpStreamState::kNew) {
      stream.state = TcpStreamState::kEstablished;
      Emit(stream, dir, StreamEventType::kOpen, {}, ts);
    }
  }

  // Fully already-received retransmission.
  if (SeqBeforeOrEqual(seq + static_cast<uint32_t>(payload.size()), half.next_expected_seq)) {
    return;
  }

  // Partial overlap: trim already-acked prefix.
  if (SeqBefore(seq, half.next_expected_seq)) {
    const uint32_t skip = half.next_expected_seq - seq;
    if (skip >= payload.size())
      return;
    seq = half.next_expected_seq;
    payload = payload.subspan(skip);
  }

  const size_t used = half.total_bytes + half.buffered_bytes;
  if (used + payload.size() > config_.max_bytes_per_stream) {
    spdlog::debug("Stream memory limit exceeded, dropping segment");
    return;
  }

  if (seq == half.next_expected_seq) {
    half.next_expected_seq = seq + static_cast<uint32_t>(payload.size());
    half.total_bytes += payload.size();
    Emit(stream, dir, StreamEventType::kData, payload, ts);
    FlushBuffered(stream, dir);
  } else if (SeqBefore(half.next_expected_seq, seq)) {
    half.buffered_bytes += payload.size();
    half.out_of_order.emplace(
        seq, BufferedSegment{std::vector<uint8_t>(payload.begin(), payload.end()), ts});
  }
}

void TcpReassembler::FlushBuffered(TcpStream& stream, int dir) {
  auto& half = stream.halves[dir];
  while (!half.out_of_order.empty()) {
    auto it = half.out_of_order.begin();
    auto& seg = it->second;

    if (SeqBeforeOrEqual(it->first + static_cast<uint32_t>(seg.data.size()),
                         half.next_expected_seq)) {
      half.buffered_bytes -= seg.data.size();
      half.out_of_order.erase(it);
      continue;
    }

    if (SeqBefore(it->first, half.next_expected_seq)) {
      const uint32_t skip = half.next_expected_seq - it->first;
      if (skip < seg.data.size()) {
        half.buffered_bytes -= skip;
        seg.data.erase(seg.data.begin(), seg.data.begin() + skip);
        auto node = half.out_of_order.extract(it);
        node.key() = half.next_expected_seq;
        half.out_of_order.insert(std::move(node));
        continue;
      }
      half.buffered_bytes -= seg.data.size();
      half.out_of_order.erase(it);
      continue;
    }

    if (it->first != half.next_expected_seq) {
      break;
    }

    half.next_expected_seq = it->first + static_cast<uint32_t>(seg.data.size());
    half.total_bytes += seg.data.size();
    half.buffered_bytes -= seg.data.size();
    Emit(stream, dir, StreamEventType::kData, seg.data, seg.timestamp);
    half.out_of_order.erase(it);
  }
}

void TcpReassembler::HandleClose(TcpStream& stream, const DissectedPacket& packet, int dir,
                                 Timestamp ts) {
  const auto& tcp = *packet.tcp;

  if (tcp.flags & tcp_flags::kRST) {
    stream.state = TcpStreamState::kClosed;
    Emit(stream, dir, StreamEventType::kClose, {}, ts);
    return;
  }

  if (tcp.flags & tcp_flags::kFIN) {
    stream.halves[dir].fin_seen = true;
    if (stream.state == TcpStreamState::kEstablished || stream.state == TcpStreamState::kNew) {
      stream.state = TcpStreamState::kClosing;
    }
    if (stream.halves[0].fin_seen && stream.halves[1].fin_seen) {
      stream.state = TcpStreamState::kClosed;
      Emit(stream, dir, StreamEventType::kClose, {}, ts);
    }
  }
}

void TcpReassembler::CloseAndErase(const ConnectionKey& key, int dir, Timestamp ts) {
  auto it = streams_.find(key);
  if (it == streams_.end())
    return;
  Emit(it->second, dir, StreamEventType::kClose, {}, ts);
  if (it->second.in_lru) {
    lru_.erase(it->second.lru_it);
  }
  streams_.erase(it);
}

void TcpReassembler::Emit(const TcpStream& stream, int dir, StreamEventType type,
                          std::span<const uint8_t> data, Timestamp ts) {
  if (!callback_)
    return;

  int client_dir = stream.client_is_src ? 0 : 1;
  auto direction =
      (dir == client_dir) ? StreamDirection::kClientToServer : StreamDirection::kServerToClient;
  StreamEvent event{
      .key = stream.key,
      .direction = direction,
      .type = type,
      .data = data,
      .timestamp = ts,
      .tcp_handshake = stream.tcp_handshake,
  };
  callback_(event);
}

void TcpReassembler::ProcessPacket(const DissectedPacket& packet, Timestamp ts) {
  if (!packet.ip || !packet.tcp)
    return;

  auto* stream = GetOrCreateStream(packet, ts);
  if (!stream)
    return;

  const auto& tcp = *packet.tcp;
  int dir = GetDirection(*stream, packet);
  const ConnectionKey key = stream->key;

  if (tcp.flags & tcp_flags::kSYN) {
    HandleSyn(*stream, packet, dir, ts);
  }
  if (!tcp.payload.empty()) {
    HandleData(*stream, dir, tcp.seq_num, tcp.payload, ts);
  }
  if (tcp.flags & (tcp_flags::kFIN | tcp_flags::kRST)) {
    HandleClose(*stream, packet, dir, ts);
    auto it = streams_.find(key);
    if (it != streams_.end() && it->second.state == TcpStreamState::kClosed) {
      if (it->second.in_lru) {
        lru_.erase(it->second.lru_it);
      }
      streams_.erase(it);
    }
  }
}

void TcpReassembler::FlushExpired(Timestamp now) {
  auto timeout = config_.idle_timeout;
  auto it = streams_.begin();
  while (it != streams_.end()) {
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_activity);
    if (elapsed >= timeout) {
      const ConnectionKey key = it->first;
      ++it;
      CloseAndErase(key, 0, now);
    } else {
      ++it;
    }
  }
}

}  // namespace wirepeek::dissector
