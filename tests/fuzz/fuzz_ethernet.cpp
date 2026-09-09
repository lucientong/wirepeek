#include <wirepeek/dissector/ethernet.h>

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  (void)wirepeek::dissector::ParseEthernet(std::span<const uint8_t>(data, size));
  return 0;
}
