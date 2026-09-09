// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/http1.h>

#include <algorithm>
#include <charconv>
#include <cctype>
#include <limits>
#include <string_view>

namespace wirepeek::protocol {

namespace {

std::string Lower(std::string_view value) {
  std::string result(value);
  std::transform(result.begin(), result.end(), result.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return result;
}

std::string_view Trim(std::string_view value) {
  const auto first = value.find_first_not_of(" \t");
  if (first == std::string_view::npos)
    return {};
  const auto last = value.find_last_not_of(" \t");
  return value.substr(first, last - first + 1);
}

bool ParseDecimal(std::string_view value, size_t& result) {
  value = Trim(value);
  if (value.empty())
    return false;
  result = 0;
  const auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), result);
  return ec == std::errc{} && ptr == value.data() + value.size();
}

}  // namespace

void Http1Parser::MessageState::Reset() {
  *this = MessageState{};
}

Http1Parser::Http1Parser(TransactionCallback callback, UpgradeCallback upgrade_callback)
    : callback_(std::move(callback)), upgrade_callback_(std::move(upgrade_callback)) {}

size_t Http1Parser::FindCrlf(const std::string& buffer, size_t pos) {
  return buffer.find("\r\n", pos);
}

void Http1Parser::Feed(std::span<const uint8_t> data, StreamDirection dir, Timestamp ts) {
  if (data.empty() || upgraded_)
    return;

  auto& buffer =
      (dir == StreamDirection::kClientToServer) ? request_buffer_ : response_buffer_;
  auto& state =
      (dir == StreamDirection::kClientToServer) ? request_state_ : response_state_;
  if (state.state == Http1ParseState::kStartLine && buffer.empty()) {
    state.timestamp = ts;
  }
  if (data.size() > kMaxMessageBytes || buffer.size() > kMaxMessageBytes - data.size()) {
    FailDirection(buffer, state);
    return;
  }
  buffer.append(reinterpret_cast<const char*>(data.data()), data.size());

  if (dir == StreamDirection::kClientToServer)
    ParseRequests(ts);
  else
    ParseResponses(ts);
}

void Http1Parser::ParseRequests(Timestamp ts) {
  while (!upgraded_) {
    if (request_state_.state == Http1ParseState::kStartLine) {
      if (request_buffer_.empty())
        return;
      if (request_state_.timestamp.time_since_epoch().count() == 0)
        request_state_.timestamp = ts;
      if (!ParseRequestLine())
        return;
      current_request_.timestamp = request_state_.timestamp;
      request_state_.state = Http1ParseState::kHeaders;
    }
    if (request_state_.state == Http1ParseState::kHeaders) {
      HeaderInfo info;
      if (!ParseHeaders(request_buffer_, current_request_.headers, info, request_state_))
        return;
      request_state_.body_mode =
          info.chunked
              ? Http1BodyMode::kChunked
              : (info.content_length && *info.content_length > 0
                     ? Http1BodyMode::kContentLength
                     : Http1BodyMode::kNone);
      request_state_.content_length = info.content_length.value_or(0);
      request_state_.state = Http1ParseState::kBody;
    }
    if (request_state_.state == Http1ParseState::kBody &&
        !ConsumeBody(request_buffer_, request_state_, current_request_.body_size))
      return;
    CompleteRequest();
    if (request_buffer_.empty())
      return;
    request_state_.timestamp = ts;
  }
}

void Http1Parser::ParseResponses(Timestamp ts) {
  while (!upgraded_) {
    if (response_state_.state == Http1ParseState::kStartLine) {
      if (response_buffer_.empty())
        return;
      if (response_state_.timestamp.time_since_epoch().count() == 0)
        response_state_.timestamp = ts;
      if (!ParseStatusLine())
        return;
      current_response_.timestamp = response_state_.timestamp;
      response_state_.state = Http1ParseState::kHeaders;
    }
    if (response_state_.state == Http1ParseState::kHeaders) {
      HeaderInfo info;
      if (!ParseHeaders(response_buffer_, current_response_.headers, info, response_state_))
        return;
      const std::string_view method =
          pending_requests_.empty() ? std::string_view{} : pending_requests_.front().method;
      if (IsNoBodyResponse(current_response_.status_code, method)) {
        response_state_.body_mode = Http1BodyMode::kNone;
      } else if (info.chunked) {
        response_state_.body_mode = Http1BodyMode::kChunked;
      } else if (info.content_length) {
        response_state_.body_mode = *info.content_length == 0 ? Http1BodyMode::kNone
                                                              : Http1BodyMode::kContentLength;
        response_state_.content_length = *info.content_length;
      } else {
        response_state_.body_mode = Http1BodyMode::kUntilClose;
      }
      response_state_.state = Http1ParseState::kBody;
    }
    if (response_state_.state == Http1ParseState::kBody &&
        !ConsumeBody(response_buffer_, response_state_, current_response_.body_size))
      return;
    response_completion_timestamp_ = ts;
    CompleteResponse();
    if (upgraded_ || response_buffer_.empty())
      return;
    response_state_.timestamp = ts;
  }
}

bool Http1Parser::ParseRequestLine() {
  const auto crlf = FindCrlf(request_buffer_);
  if (crlf == std::string::npos) {
    if (request_buffer_.size() > kMaxStartLineBytes)
      FailDirection(request_buffer_, request_state_);
    return false;
  }
  if (crlf > kMaxStartLineBytes) {
    FailDirection(request_buffer_, request_state_);
    return false;
  }

  const std::string line = request_buffer_.substr(0, crlf);
  const auto sp1 = line.find(' ');
  const auto sp2 = sp1 == std::string::npos ? std::string::npos : line.find(' ', sp1 + 1);
  if (sp1 == std::string::npos || sp1 == 0 || sp2 == std::string::npos || sp2 == sp1 + 1 ||
      sp2 + 1 >= line.size()) {
    FailDirection(request_buffer_, request_state_);
    return false;
  }
  current_request_.method = line.substr(0, sp1);
  current_request_.url = line.substr(sp1 + 1, sp2 - sp1 - 1);
  current_request_.version = line.substr(sp2 + 1);
  request_buffer_.erase(0, crlf + 2);
  request_state_.message_bytes += crlf + 2;
  return true;
}

bool Http1Parser::ParseStatusLine() {
  const auto crlf = FindCrlf(response_buffer_);
  if (crlf == std::string::npos) {
    if (response_buffer_.size() > kMaxStartLineBytes)
      FailDirection(response_buffer_, response_state_);
    return false;
  }
  if (crlf > kMaxStartLineBytes) {
    FailDirection(response_buffer_, response_state_);
    return false;
  }

  const std::string line = response_buffer_.substr(0, crlf);
  const auto sp1 = line.find(' ');
  const auto sp2 = sp1 == std::string::npos ? std::string::npos : line.find(' ', sp1 + 1);
  if (sp1 == std::string::npos || sp1 == 0) {
    FailDirection(response_buffer_, response_state_);
    return false;
  }
  const std::string_view status(line.data() + sp1 + 1,
                                (sp2 == std::string::npos ? line.size() : sp2) - sp1 - 1);
  unsigned int parsed_status = 0;
  const auto [ptr, ec] =
      std::from_chars(status.data(), status.data() + status.size(), parsed_status);
  if (ec != std::errc{} || ptr != status.data() + status.size() || parsed_status > 999) {
    FailDirection(response_buffer_, response_state_);
    return false;
  }
  current_response_.version = line.substr(0, sp1);
  current_response_.status_code = static_cast<uint16_t>(parsed_status);
  current_response_.reason = sp2 == std::string::npos ? "" : line.substr(sp2 + 1);
  response_buffer_.erase(0, crlf + 2);
  response_state_.message_bytes += crlf + 2;
  return true;
}

bool Http1Parser::ParseHeaders(std::string& buffer, std::vector<HttpHeader>& headers,
                               HeaderInfo& info, MessageState& state) {
  const bool empty_headers = buffer.starts_with("\r\n");
  const auto end = empty_headers ? size_t{0} : buffer.find("\r\n\r\n");
  if (end == std::string::npos) {
    if (buffer.size() > kMaxHeaderBytes)
      FailDirection(buffer, state);
    return false;
  }
  const size_t consumed_bytes = empty_headers ? 2 : end + 4;
  if (consumed_bytes > kMaxHeaderBytes ||
      state.message_bytes > kMaxMessageBytes - consumed_bytes) {
    FailDirection(buffer, state);
    return false;
  }

  size_t pos = 0;
  while (pos < end) {
    const auto crlf = buffer.find("\r\n", pos);
    const auto line_end = std::min(crlf, end);
    const std::string_view line(buffer.data() + pos, line_end - pos);
    const auto colon = line.find(':');
    if (colon == std::string_view::npos || colon == 0) {
      FailDirection(buffer, state);
      return false;
    }
    std::string name(line.substr(0, colon));
    std::string value(Trim(line.substr(colon + 1)));
    const auto lower_name = Lower(name);
    if (lower_name == "content-length") {
      size_t parsed = 0;
      if (!ParseDecimal(value, parsed) ||
          (info.content_length && *info.content_length != parsed)) {
        FailDirection(buffer, state);
        return false;
      }
      info.content_length = parsed;
    } else if (lower_name == "transfer-encoding") {
      const auto lower_value = Lower(value);
      size_t token_start = 0;
      while (token_start <= lower_value.size()) {
        const auto comma = lower_value.find(',', token_start);
        const auto token = Trim(std::string_view(lower_value).substr(
            token_start, comma == std::string::npos ? std::string::npos : comma - token_start));
        if (token == "chunked")
          info.chunked = true;
        if (comma == std::string::npos)
          break;
        token_start = comma + 1;
      }
    }
    headers.emplace_back(std::move(name), std::move(value));
    pos = line_end + 2;
  }
  buffer.erase(0, consumed_bytes);
  state.message_bytes += consumed_bytes;
  return true;
}

bool Http1Parser::ConsumeBody(std::string& buffer, MessageState& state, size_t& body_size) {
  switch (state.body_mode) {
    case Http1BodyMode::kNone:
      return true;
    case Http1BodyMode::kUntilClose:
      if (body_size > kMaxBodyBytes - buffer.size()) {
        FailDirection(buffer, state);
        return false;
      }
      body_size += buffer.size();
      state.message_bytes += buffer.size();
      buffer.clear();
      return false;
    case Http1BodyMode::kContentLength: {
      const size_t remaining = state.content_length - state.body_read;
      const size_t consumed = std::min(remaining, buffer.size());
      state.body_read += consumed;
      body_size += consumed;
      state.message_bytes += consumed;
      buffer.erase(0, consumed);
      if (state.content_length > kMaxBodyBytes || state.message_bytes > kMaxMessageBytes) {
        FailDirection(buffer, state);
        return false;
      }
      return state.body_read == state.content_length;
    }
    case Http1BodyMode::kChunked:
      return ConsumeChunked(buffer, state, body_size);
  }
  return false;
}

bool Http1Parser::ConsumeChunked(std::string& buffer, MessageState& state, size_t& body_size) {
  while (true) {
    if (state.reading_trailers) {
      if (buffer.starts_with("\r\n")) {
        buffer.erase(0, 2);
        state.message_bytes += 2;
        return true;
      }
      const auto end = buffer.find("\r\n\r\n");
      if (end == std::string::npos) {
        if (buffer.size() > kMaxHeaderBytes)
          FailDirection(buffer, state);
        return false;
      }
      buffer.erase(0, end + 4);
      state.message_bytes += end + 4;
      return true;
    }
    if (state.chunk_remaining == 0) {
      const auto crlf = FindCrlf(buffer);
      if (crlf == std::string::npos) {
        if (buffer.size() > kMaxStartLineBytes)
          FailDirection(buffer, state);
        return false;
      }
      const std::string_view line(buffer.data(), crlf);
      const auto semicolon = line.find(';');
      const auto size_text = Trim(line.substr(0, semicolon));
      size_t chunk_size = 0;
      const auto [ptr, ec] =
          std::from_chars(size_text.data(), size_text.data() + size_text.size(), chunk_size, 16);
      if (size_text.empty() || ec != std::errc{} || ptr != size_text.data() + size_text.size() ||
          chunk_size > kMaxBodyBytes - body_size) {
        FailDirection(buffer, state);
        return false;
      }
      buffer.erase(0, crlf + 2);
      state.message_bytes += crlf + 2;
      if (chunk_size == 0) {
        state.reading_trailers = true;
        continue;
      }
      state.chunk_remaining = chunk_size;
    }
    if (buffer.size() < state.chunk_remaining + 2)
      return false;
    if (buffer[state.chunk_remaining] != '\r' || buffer[state.chunk_remaining + 1] != '\n') {
      FailDirection(buffer, state);
      return false;
    }
    body_size += state.chunk_remaining;
    state.message_bytes += state.chunk_remaining + 2;
    buffer.erase(0, state.chunk_remaining + 2);
    state.chunk_remaining = 0;
    if (body_size > kMaxBodyBytes || state.message_bytes > kMaxMessageBytes) {
      FailDirection(buffer, state);
      return false;
    }
  }
}

void Http1Parser::CompleteRequest() {
  pending_requests_.push_back(std::move(current_request_));
  ResetRequest();
}

void Http1Parser::CompleteResponse() {
  const uint16_t status = current_response_.status_code;
  if (status >= 100 && status < 200 && status != 101) {
    ResetResponse();
    return;
  }
  if (!pending_requests_.empty()) {
    auto request = std::move(pending_requests_.front());
    pending_requests_.pop_front();
    auto response = std::move(current_response_);
    EmitPair(std::move(request), std::move(response), true);
  }
  const bool upgrade = status == 101;
  ResetResponse();
  if (upgrade) {
    upgraded_ = true;
    if (upgrade_callback_)
      upgrade_callback_();
  }
}

void Http1Parser::EmitPair(HttpRequest request, HttpResponse response, bool complete) {
  HttpTransaction transaction;
  transaction.request = std::move(request);
  transaction.response = std::move(response);
  transaction.complete = complete;
  if (transaction.request.timestamp.time_since_epoch().count() > 0 &&
      transaction.response.timestamp.time_since_epoch().count() > 0) {
    transaction.latency = std::chrono::duration_cast<std::chrono::microseconds>(
        transaction.response.timestamp - transaction.request.timestamp);
    transaction.timing.ttfb = transaction.latency;
    if (response_completion_timestamp_.time_since_epoch().count() > 0)
      transaction.timing.transfer = std::chrono::duration_cast<std::chrono::microseconds>(
          response_completion_timestamp_ - transaction.response.timestamp);
  }
  if (callback_)
    callback_(transaction);
}

void Http1Parser::ResetRequest() {
  current_request_ = HttpRequest{};
  request_state_.Reset();
}

void Http1Parser::ResetResponse() {
  current_response_ = HttpResponse{};
  response_state_.Reset();
  response_completion_timestamp_ = Timestamp{};
}

void Http1Parser::FailDirection(std::string& buffer, MessageState& state) {
  buffer.clear();
  state.Reset();
  if (&state == &request_state_)
    current_request_ = HttpRequest{};
  else
    current_response_ = HttpResponse{};
}

bool Http1Parser::HeaderContainsToken(const std::vector<HttpHeader>& headers,
                                      std::string_view name, std::string_view token) {
  const auto wanted_name = Lower(name);
  const auto wanted_token = Lower(token);
  for (const auto& [header_name, header_value] : headers) {
    if (Lower(header_name) != wanted_name)
      continue;
    const auto value = Lower(header_value);
    size_t start = 0;
    while (start <= value.size()) {
      const auto comma = value.find(',', start);
      if (Trim(std::string_view(value).substr(
              start, comma == std::string::npos ? std::string::npos : comma - start)) ==
          wanted_token)
        return true;
      if (comma == std::string::npos)
        break;
      start = comma + 1;
    }
  }
  return false;
}

bool Http1Parser::IsNoBodyResponse(uint16_t status, std::string_view request_method) {
  return request_method == "HEAD" || (status >= 100 && status < 200) || status == 204 ||
         status == 304;
}

void Http1Parser::OnClose() {
  if (response_state_.state == Http1ParseState::kBody &&
      response_state_.body_mode == Http1BodyMode::kUntilClose) {
    current_response_.body_size += response_buffer_.size();
    response_buffer_.clear();
    CompleteResponse();
  } else if (current_response_.status_code != 0 && !pending_requests_.empty()) {
    auto request = std::move(pending_requests_.front());
    pending_requests_.pop_front();
    EmitPair(std::move(request), std::move(current_response_), false);
    ResetResponse();
  }

  while (!pending_requests_.empty()) {
    auto request = std::move(pending_requests_.front());
    pending_requests_.pop_front();
    EmitPair(std::move(request), HttpResponse{}, false);
  }
  if (!current_request_.method.empty())
    EmitPair(std::move(current_request_), HttpResponse{}, false);
  ResetRequest();
  ResetResponse();
  request_buffer_.clear();
  response_buffer_.clear();
}

}  // namespace wirepeek::protocol
