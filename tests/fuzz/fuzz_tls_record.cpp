#include <wirepeek/protocol/tls_record.h>

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  wirepeek::protocol::TlsRecordFramer framer;
  wirepeek::protocol::TlsHandshakeReassembler hs;
  const auto bytes = std::span<const uint8_t>(data, size);
  for (auto& record : framer.Feed(bytes)) {
    if (record.type == wirepeek::protocol::TlsContentType::kHandshake)
      (void)hs.Feed(record.payload);
  }
  return 0;
}
