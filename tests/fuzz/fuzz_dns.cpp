#include <wirepeek/protocol/dns.h>

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const auto bytes = std::span<const uint8_t>(data, size);
  (void)wirepeek::protocol::ParseDnsQuery(bytes);
  (void)wirepeek::protocol::ParseDnsResponse(bytes);
  return 0;
}
