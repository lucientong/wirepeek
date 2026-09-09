#include <wirepeek/protocol/detector.h>
#include <wirepeek/protocol/http1.h>

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const auto bytes = std::span<const uint8_t>(data, size);
  const auto payload = size > 0 ? bytes.subspan(1) : bytes;
  (void)wirepeek::protocol::DetectProtocol(payload);

  wirepeek::protocol::Http1Parser parser([](const wirepeek::HttpTransaction&) {});
  const auto direction = size > 0 && (data[0] & 1U) != 0
                             ? wirepeek::StreamDirection::kServerToClient
                             : wirepeek::StreamDirection::kClientToServer;
  parser.Feed(payload, direction, wirepeek::Timestamp{});
  parser.OnClose();
  return 0;
}
