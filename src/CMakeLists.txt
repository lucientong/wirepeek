# ── wirepeek_lib: core library ─────────────────────────────────────────────────

add_library(wirepeek_lib STATIC
  dissector/ethernet.cpp
  dissector/ip.cpp
  dissector/tcp.cpp
  dissector/udp.cpp
  dissector/dissect.cpp
  dissector/tcp_reassembler.cpp
  protocol/detector.cpp
  protocol/http1.cpp
  protocol/protocol_handler.cpp
  analyzer/tdigest.cpp
  analyzer/statistics.cpp
  tui/app.cpp
  capture/pcap_source.cpp
  capture/file_source.cpp
)

target_include_directories(wirepeek_lib PUBLIC
  ${PROJECT_SOURCE_DIR}/include
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

# ── wirepeek: main executable ─────────────────────────────────────────────────

add_executable(wirepeek
  cli/main.cpp
)

target_link_libraries(wirepeek PRIVATE
  wirepeek_lib
  CLI11::CLI11
)
