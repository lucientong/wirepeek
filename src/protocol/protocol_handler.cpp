// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/detector.h>
#include <wirepeek/protocol/dns.h>
#include <wirepeek/protocol/protocol_handler.h>
#include <wirepeek/protocol/tls.h>
#include <wirepeek/protocol/websocket.h>

#include <algorithm>
#include <limits>
#include <spdlog/spdlog.h>

namespace wirepeek::protocol {

namespace {

size_t DirectionIndex(StreamDirection direction) {
  return direction == StreamDirection::kClientToServer ? 0 : 1;
}

bool IsReverseFlow(const ConnectionKey& query, const ConnectionKey& response) {
  return query.src_ip == response.dst_ip && query.dst_ip == response.src_ip &&
         query.src_port == response.dst_port && query.dst_port == response.src_port &&
         query.ip_version == response.ip_version && query.protocol == response.protocol;
}

bool CouldBeKnownProtocolPrefix(std::span<const uint8_t> data) {
  static constexpr std::array<std::string_view, 12> kPrefixes = {
      "GET ",   "POST ",    "PUT ",   "DELETE ", "HEAD ",        "OPTIONS ",
      "PATCH ", "CONNECT ", "TRACE ", "HTTP/",   "PRI * HTTP/2", "\x16\x03"};
  return std::any_of(kPrefixes.begin(), kPrefixes.end(),
                     [data](std::string_view prefix) {
                       return data.size() < prefix.size() &&
                              std::equal(data.begin(), data.end(),
                                         reinterpret_cast<const uint8_t*>(prefix.data()));
                     }) ||
         (data.size() < 3 && !data.empty() &&
          std::string_view("*+$-:").find(static_cast<char>(data.front())) !=
              std::string_view::npos);
}

size_t WsFrameSize(std::span<const uint8_t> data, const WsFrameInfo& frame) {
  const uint8_t length_code = data[1] & 0x7f;
  size_t header_size = 2;
  if (length_code == 126)
    header_size += 2;
  else if (length_code == 127)
    header_size += 8;
  if (frame.masked)
    header_size += 4;
  if (frame.payload_len > std::numeric_limits<size_t>::max() - header_size)
    return 0;
  return header_size + frame.payload_len;
}

}  // namespace

ProtocolHandler::ProtocolHandler(EventCallback callback) : callback_(std::move(callback)) {}

ProtocolHandler::ProtocolHandler(HttpCallback http_callback, RawDataCallback raw_callback)
    : ProtocolHandler(
          [http_callback = std::move(http_callback), raw_callback = std::move(raw_callback)](
              const ConnectionKey& key, const AppEvent& event) {
            if (const auto* transaction = std::get_if<HttpTransaction>(&event)) {
              if (http_callback)
                http_callback(key, *transaction);
            } else if (const auto* raw = std::get_if<RawFlowEvent>(&event)) {
              if (raw_callback) {
                std::vector<uint8_t> data(raw->bytes);
                raw_callback(key, raw->dir, data);
              }
            }
          }) {}

void ProtocolHandler::Emit(const ConnectionKey& key, AppEvent event) const {
  if (callback_)
    callback_(key, event);
}

void ProtocolHandler::FeedTls(const ConnectionKey& key, TlsStreamState& state,
                              std::span<const uint8_t> data, StreamDirection direction,
                              Timestamp ts) {
  const size_t index = DirectionIndex(direction);
  if (state.parsed[index])
    return;

  auto& buffer = state.buffers[index];
  buffer.insert(buffer.end(), data.begin(), data.end());
  if (buffer.size() > 256 * 1024) {
    buffer.clear();
    state.parsed[index] = true;
    return;
  }

  std::optional<TlsHandshakeInfo> info;
  if (direction == StreamDirection::kClientToServer)
    info = ParseTlsClientHello(buffer);
  else
    info = ParseTlsServerHello(buffer);
  if (!info)
    return;

  info->timestamp = ts;
  state.parsed[index] = true;
  buffer.clear();
  Emit(key, std::move(*info));
}

void ProtocolHandler::FeedWebSocket(const ConnectionKey& key, WsStreamState& state,
                                    std::span<const uint8_t> data, StreamDirection direction) {
  auto& buffer = state.buffers[DirectionIndex(direction)];
  buffer.insert(buffer.end(), data.begin(), data.end());
  if (buffer.size() > 64 * 1024 * 1024) {
    buffer.clear();
    return;
  }

  while (!buffer.empty()) {
    auto frame = ParseWsFrame(buffer);
    if (!frame)
      return;
    const size_t frame_size = WsFrameSize(buffer, *frame);
    if (frame_size == 0 || buffer.size() < frame_size)
      return;
    Emit(key, WebSocketEvent{.key = key, .frame = *frame});
    buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(frame_size));
  }
}

void ProtocolHandler::OnStreamEvent(const dissector::StreamEvent& event, Timestamp ts) {
  switch (event.type) {
    case dissector::StreamEventType::kOpen: {
      // Create stream state.
      streams_[event.key] = StreamState{};
      break;
    }

    case dissector::StreamEventType::kData: {
      auto it = streams_.find(event.key);
      if (it == streams_.end()) {
        // Stream not tracked (opened before handler was attached). Create it.
        it = streams_.emplace(event.key, StreamState{}).first;
      }

      auto& state = it->second;
      if (event.tcp_handshake)
        state.tcp_handshake = event.tcp_handshake;
      bool newly_detected = false;

      // Detect protocol on first data.
      if (!state.detected && !event.data.empty()) {
        state.detection_buffer.insert(state.detection_buffer.end(), event.data.begin(),
                                      event.data.end());
        state.protocol = DetectProtocol(state.detection_buffer);
        if (state.protocol == AppProtocol::kUnknown &&
            CouldBeKnownProtocolPrefix(state.detection_buffer))
          break;
        state.detected = true;
        newly_detected = true;

        if (state.protocol == AppProtocol::kHttp1) {
          const auto& key = event.key;
          state.parser = std::make_unique<Http1Parser>([this, key](const HttpTransaction& txn) {
            auto stream = streams_.find(key);
            HttpTransaction timed = txn;
            if (stream != streams_.end() && txn.response.status_code == 101 &&
                IsWebSocketUpgrade(txn.request)) {
              stream->second.websocket_upgrade = true;
            }
            if (stream != streams_.end())
              timed.timing.tcp_handshake = stream->second.tcp_handshake;
            Emit(key, std::move(timed));
          });
        } else if (state.protocol == AppProtocol::kHttp2) {
          state.parser = std::make_unique<Http2Parser>(
              [this, key = event.key](const Http2StreamEvent& frame) { Emit(key, frame); });
        } else if (state.protocol == AppProtocol::kRedis) {
          state.parser = std::make_unique<RedisParser>(
              [this, key = event.key](const RedisTransaction& txn) { Emit(key, txn); });
        } else if (state.protocol == AppProtocol::kTls) {
          state.parser = TlsStreamState{};
        }

        spdlog::debug("Detected protocol: {}", AppProtocolName(state.protocol));
      }

      const std::span<const uint8_t> routed_data =
          newly_detected ? std::span<const uint8_t>(state.detection_buffer) : event.data;

      // Route to parser.
      if (auto* parser = std::get_if<std::unique_ptr<Http1Parser>>(&state.parser)) {
        (*parser)->Feed(routed_data, event.direction, ts);
        if ((*parser)->IsUpgraded() && state.websocket_upgrade)
          state.parser = WsStreamState{};
      } else if (auto* tls = std::get_if<TlsStreamState>(&state.parser)) {
        FeedTls(event.key, *tls, routed_data, event.direction, ts);
      } else if (auto* h2 = std::get_if<std::unique_ptr<Http2Parser>>(&state.parser)) {
        (*h2)->Feed(routed_data, event.direction, ts);
      } else if (auto* redis = std::get_if<std::unique_ptr<RedisParser>>(&state.parser)) {
        (*redis)->Feed(routed_data, event.direction, ts);
      } else if (auto* ws = std::get_if<WsStreamState>(&state.parser)) {
        FeedWebSocket(event.key, *ws, routed_data, event.direction);
      } else {
        Emit(event.key, RawFlowEvent{.key = event.key,
                                     .dir = event.direction,
                                     .bytes = routed_data.size(),
                                     .ts = ts,
                                     .protocol = state.protocol});
      }
      if (newly_detected)
        state.detection_buffer.clear();
      break;
    }

    case dissector::StreamEventType::kClose: {
      auto it = streams_.find(event.key);
      if (it != streams_.end()) {
        if (auto* parser = std::get_if<std::unique_ptr<Http1Parser>>(&it->second.parser))
          (*parser)->OnClose();
        else if (auto* parser = std::get_if<std::unique_ptr<RedisParser>>(&it->second.parser))
          (*parser)->OnClose();
        streams_.erase(it);
      }
      break;
    }
  }
}

void ProtocolHandler::OnUdpPayload(const ConnectionKey& key, std::span<const uint8_t> payload,
                                   Timestamp ts) {
  if (key.src_port != 53 && key.dst_port != 53 && !LooksDnsShaped(payload))
    return;

  if (auto query = ParseDnsQuery(payload)) {
    query->timestamp = ts;
    auto& pending = pending_dns_[query->id];
    pending.push_back(PendingDns{.key = key, .query = std::move(*query)});
    if (pending.size() > 64)
      pending.erase(pending.begin());
    return;
  }

  auto response = ParseDnsResponse(payload);
  if (!response)
    return;
  response->timestamp = ts;

  auto pending_it = pending_dns_.find(response->id);
  if (pending_it == pending_dns_.end())
    return;
  auto& candidates = pending_it->second;
  auto match = std::find_if(candidates.begin(), candidates.end(), [&key](const PendingDns& item) {
    return IsReverseFlow(item.key, key);
  });
  if (match == candidates.end())
    return;

  DnsEvent event;
  event.query = match->query;
  event.response = std::move(*response);
  event.latency = std::chrono::duration_cast<std::chrono::microseconds>(ts - event.query.timestamp);
  event.complete = true;
  const ConnectionKey query_key = match->key;
  candidates.erase(match);
  if (candidates.empty())
    pending_dns_.erase(pending_it);
  Emit(query_key, std::move(event));
}

}  // namespace wirepeek::protocol
