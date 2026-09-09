set(WIREPEEK_FUZZ_TARGETS
  fuzz_ethernet
  fuzz_ip
  fuzz_tcp
  fuzz_udp
  fuzz_dns
  fuzz_tls
  fuzz_tls_record
  fuzz_websocket
  fuzz_http1
)

foreach(target IN LISTS WIREPEEK_FUZZ_TARGETS)
  add_executable(${target} ${target}.cpp)
  target_link_libraries(${target} PRIVATE wirepeek_lib)
  target_compile_options(${target} PRIVATE -fsanitize=fuzzer,address -fno-omit-frame-pointer)
  target_link_options(${target} PRIVATE -fsanitize=fuzzer,address)
endforeach()
