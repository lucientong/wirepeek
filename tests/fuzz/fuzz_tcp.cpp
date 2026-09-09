#include <wirepeek/dissector/tcp.h>

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  (void)wirepeek::dissector::ParseTcp(std::span<const uint8_t>(data, size));
  return 0;
}
