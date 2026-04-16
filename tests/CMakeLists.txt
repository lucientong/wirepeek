add_executable(wirepeek_tests
  unit/test_ethernet.cpp
  unit/test_ip.cpp
  unit/test_tcp.cpp
  unit/test_udp.cpp
  unit/test_dissect.cpp
  unit/test_packet.cpp
  unit/test_stream.cpp
  unit/test_tcp_reassembler.cpp
  unit/test_detector.cpp
  unit/test_http1.cpp
)

target_link_libraries(wirepeek_tests PRIVATE
  wirepeek_lib
  GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(wirepeek_tests)
