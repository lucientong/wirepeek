#include <wirepeek/protocol/detector.h>
#include <wirepeek/protocol/websocket.h>

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const auto bytes = std::span<const uint8_t>(data, size);
  (void)wirepeek::protocol::DetectProtocol(bytes);
  (void)wirepeek::protocol::ParseWsFrame(bytes);
  return 0;
}
