// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/protocol/http1.h>

#include <algorithm>
#include <charconv>
#include <spdlog/spdlog.h>

namespace wirepeek::protocol {

Http1Parser::Http1Parser(TransactionCallback callback) : callback_(std::move(callback)) {}

size_t Http1Parser::FindCrlf(const std::string& buffer, size_t pos) {
  auto idx = buffer.find("\r\n", pos);
  return idx;
}

void Http1Parser::Feed(std::span<const uint8_t> data, StreamDirection dir, Timestamp ts) {
  if (data.empty())
    return;

  if (dir == StreamDirection::kClientToServer) {
    request_buffer_.append(reinterpret_cast<const char*>(data.data()), data.size());
  } else {
    response_buffer_.append(reinterpret_cast<const char*>(data.data()), data.size());
  }

  Parse(dir, ts);
}

void Http1Parser::Parse(StreamDirection dir, Timestamp ts) {
  if (dir == StreamDirection::kClientToServer) {
    // Parse request.
    while (true) {
      if (request_state_ == Http1ParseState::kStartLine) {
        if (!ParseRequestLine())
          break;
        current_.request.timestamp = ts;
        request_state_ = Http1ParseState::kHeaders;
      }
      if (request_state_ == Http1ParseState::kHeaders) {
        if (!ParseHeaders(request_buffer_, current_.request.headers, request_content_length_))
          break;
        request_state_ = Http1ParseState::kBody;
        request_body_read_ = 0;
      }
      if (request_state_ == Http1ParseState::kBody) {
        if (request_content_length_ > 0) {
          size_t available = request_buffer_.size();
          size_t remaining = request_content_length_ - request_body_read_;
          size_t consume = std::min(available, remaining);
          request_body_read_ += consume;
          request_buffer_.erase(0, consume);
          if (request_body_read_ < request_content_length_)
            break;
        }
        current_.request.body_size = request_content_length_;
        request_state_ = Http1ParseState::kComplete;
      }
      if (request_state_ == Http1ParseState::kComplete) {
        has_request_ = true;
        request_state_ = Http1ParseState::kStartLine;
        request_content_length_ = 0;
        if (has_response_)
          EmitTransaction();
        break;  // Wait for more data or next request.
      }
    }
  } else {
    // Parse response.
    while (true) {
      if (response_state_ == Http1ParseState::kStartLine) {
        if (!ParseStatusLine())
          break;
        current_.response.timestamp = ts;
        response_state_ = Http1ParseState::kHeaders;
      }
      if (response_state_ == Http1ParseState::kHeaders) {
        if (!ParseHeaders(response_buffer_, current_.response.headers, response_content_length_))
          break;
        response_state_ = Http1ParseState::kBody;
        response_body_read_ = 0;
      }
      if (response_state_ == Http1ParseState::kBody) {
        if (response_content_length_ > 0) {
          size_t available = response_buffer_.size();
          size_t remaining = response_content_length_ - response_body_read_;
          size_t consume = std::min(available, remaining);
          response_body_read_ += consume;
          response_buffer_.erase(0, consume);
          if (response_body_read_ < response_content_length_)
            break;
        }
        current_.response.body_size = response_content_length_;
        response_state_ = Http1ParseState::kComplete;
      }
      if (response_state_ == Http1ParseState::kComplete) {
        has_response_ = true;
        response_state_ = Http1ParseState::kStartLine;
        response_content_length_ = 0;
        if (has_request_)
          EmitTransaction();
        break;
      }
    }
  }
}

bool Http1Parser::ParseRequestLine() {
  auto crlf = FindCrlf(request_buffer_);
  if (crlf == std::string::npos)
    return false;

  std::string line = request_buffer_.substr(0, crlf);
  request_buffer_.erase(0, crlf + 2);

  // "METHOD SP URL SP VERSION"
  auto sp1 = line.find(' ');
  if (sp1 == std::string::npos)
    return false;
  auto sp2 = line.find(' ', sp1 + 1);
  if (sp2 == std::string::npos)
    return false;

  current_.request.method = line.substr(0, sp1);
  current_.request.url = line.substr(sp1 + 1, sp2 - sp1 - 1);
  current_.request.version = line.substr(sp2 + 1);

  return true;
}

bool Http1Parser::ParseStatusLine() {
  auto crlf = FindCrlf(response_buffer_);
  if (crlf == std::string::npos)
    return false;

  std::string line = response_buffer_.substr(0, crlf);
  response_buffer_.erase(0, crlf + 2);

  // "VERSION SP STATUS SP REASON"
  auto sp1 = line.find(' ');
  if (sp1 == std::string::npos)
    return false;
  auto sp2 = line.find(' ', sp1 + 1);

  current_.response.version = line.substr(0, sp1);

  std::string status_str;
  if (sp2 != std::string::npos) {
    status_str = line.substr(sp1 + 1, sp2 - sp1 - 1);
    current_.response.reason = line.substr(sp2 + 1);
  } else {
    status_str = line.substr(sp1 + 1);
  }

  auto [ptr, ec] = std::from_chars(status_str.data(), status_str.data() + status_str.size(),
                                   current_.response.status_code);
  if (ec != std::errc{}) {
    current_.response.status_code = 0;
  }

  return true;
}

bool Http1Parser::ParseHeaders(std::string& buffer, std::vector<HttpHeader>& headers,
                               size_t& content_length) {
  content_length = 0;
  while (true) {
    auto crlf = FindCrlf(buffer);
    if (crlf == std::string::npos)
      return false;

    if (crlf == 0) {
      // Empty line — end of headers.
      buffer.erase(0, 2);
      return true;
    }

    std::string line = buffer.substr(0, crlf);
    buffer.erase(0, crlf + 2);

    auto colon = line.find(':');
    if (colon == std::string::npos)
      continue;

    std::string name = line.substr(0, colon);
    std::string value = line.substr(colon + 1);
    // Trim leading whitespace from value.
    auto first_non_space = value.find_first_not_of(" \t");
    if (first_non_space != std::string::npos) {
      value = value.substr(first_non_space);
    }

    // Check for Content-Length.
    // Case-insensitive comparison.
    std::string name_lower = name;
    std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (name_lower == "content-length") {
      std::from_chars(value.data(), value.data() + value.size(), content_length);
    }

    headers.emplace_back(std::move(name), std::move(value));
  }
}

void Http1Parser::EmitTransaction() {
  if (!callback_)
    return;

  // Calculate latency if both timestamps are available.
  if (current_.request.timestamp.time_since_epoch().count() > 0 &&
      current_.response.timestamp.time_since_epoch().count() > 0) {
    current_.latency = std::chrono::duration_cast<std::chrono::microseconds>(
        current_.response.timestamp - current_.request.timestamp);
  }
  current_.complete = true;

  callback_(current_);

  // Reset for next transaction.
  has_request_ = false;
  has_response_ = false;
  current_ = HttpTransaction{};
}

void Http1Parser::OnClose() {
  // If we have a partial transaction (request without response), emit it.
  if (has_request_ && !has_response_) {
    current_.complete = false;
    if (callback_)
      callback_(current_);
  }
  has_request_ = false;
  has_response_ = false;
}

}  // namespace wirepeek::protocol
