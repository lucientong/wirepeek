# ── wirepeek_lib: core library ─────────────────────────────────────────────────

add_library(wirepeek_lib STATIC
  dissector/ethernet.cpp
  dissector/ip.cpp
  dissector/tcp.cpp
  dissector/udp.cpp
  dissector/link.cpp
  dissector/dissect.cpp
  dissector/tcp_reassembler.cpp
  protocol/detector.cpp
  protocol/http1.cpp
  protocol/http2.cpp
  protocol/redis.cpp
  protocol/dns.cpp
  protocol/tls.cpp
  protocol/tls_record.cpp
  protocol/tls_keylog.cpp
  protocol/tls_cipher.cpp
  protocol/tls_crypto.cpp
  protocol/tls_decryptor.cpp
  protocol/tls_session.cpp
  protocol/websocket.cpp
  protocol/protocol_handler.cpp
  analyzer/tdigest.cpp
  analyzer/statistics.cpp
  analyzer/endpoint_stats.cpp
  analyzer/metrics_server.cpp
  export/pcap_writer.cpp
  export/har_writer.cpp
  export/json_writer.cpp
  tui/app.cpp
  capture/pcap_source.cpp
  capture/file_source.cpp
)

target_include_directories(wirepeek_lib PUBLIC
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_BINARY_DIR}/generated
)

target_link_libraries(wirepeek_lib PUBLIC
  fmt::fmt
  spdlog::spdlog
  Pcap::Pcap
  xxhash
  ftxui::screen
  ftxui::dom
  ftxui::component
)

if(WIREPEEK_ENABLE_TLS_DECRYPT)
  target_link_libraries(wirepeek_lib PUBLIC OpenSSL::Crypto)
  target_compile_definitions(wirepeek_lib PUBLIC WIREPEEK_ENABLE_TLS_DECRYPT=1)
endif()

# ── wirepeek: main executable ─────────────────────────────────────────────────

add_executable(wirepeek
  cli/main.cpp
)

target_link_libraries(wirepeek PRIVATE
  wirepeek_lib
  CLI11::CLI11
)
