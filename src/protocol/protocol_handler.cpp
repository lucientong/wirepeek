// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/detector.h>
#include <wirepeek/protocol/protocol_handler.h>

#include <spdlog/spdlog.h>

namespace wirepeek::protocol {

ProtocolHandler::ProtocolHandler(HttpCallback http_cb, RawDataCallback raw_cb)
    : http_callback_(std::move(http_cb)), raw_callback_(std::move(raw_cb)) {}

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

      // Detect protocol on first data.
      if (!state.detected && !event.data.empty()) {
        state.protocol = DetectProtocol(event.data);
        state.detected = true;

        if (state.protocol == AppProtocol::kHttp1) {
          const auto& key = event.key;
          state.http_parser =
              std::make_unique<Http1Parser>([this, key](const HttpTransaction& txn) {
                if (http_callback_)
                  http_callback_(key, txn);
              });
        }

        spdlog::debug("Detected protocol: {}", AppProtocolName(state.protocol));
      }

      // Route to parser.
      if (state.http_parser) {
        state.http_parser->Feed(event.data, event.direction, ts);
      } else if (raw_callback_) {
        raw_callback_(event.key, event.direction, event.data);
      }
      break;
    }

    case dissector::StreamEventType::kClose: {
      auto it = streams_.find(event.key);
      if (it != streams_.end()) {
        if (it->second.http_parser) {
          it->second.http_parser->OnClose();
        }
        streams_.erase(it);
      }
      break;
    }
  }
}

}  // namespace wirepeek::protocol
