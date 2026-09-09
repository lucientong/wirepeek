add_executable(wirepeek_tests
  unit/test_ethernet.cpp
  unit/test_ip.cpp
  unit/test_tcp.cpp
  unit/test_udp.cpp
  unit/test_dissect.cpp
  unit/test_packet.cpp
  unit/test_spsc_queue.cpp
  unit/test_stream.cpp
  unit/test_tcp_reassembler.cpp
  unit/test_detector.cpp
  unit/test_http1.cpp
  unit/test_http2.cpp
  unit/test_redis.cpp
  unit/test_protocol_handler.cpp
  unit/test_tdigest.cpp
  unit/test_statistics.cpp
  unit/test_endpoint_stats.cpp
  unit/test_stage5_support.cpp
  unit/test_dns.cpp
  unit/test_tls.cpp
  unit/test_websocket.cpp
  unit/test_export.cpp
  unit/test_ui_state.cpp
)

target_link_libraries(wirepeek_tests PRIVATE
  wirepeek_lib
  GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(wirepeek_tests)

add_dependencies(wirepeek_tests wirepeek)

add_test(
  NAME cli_read_integration
  COMMAND ${CMAKE_COMMAND} -E env
    "WIREPEEK_BIN=$<TARGET_FILE:wirepeek>"
    "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_cli_read.sh"
)
