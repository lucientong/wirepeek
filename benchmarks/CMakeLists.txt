set(WIREPEEK_BENCHMARK_TARGETS
  bench_dissect
  bench_reassemble
  bench_http1
  bench_e2e_pcap
)

foreach(target IN LISTS WIREPEEK_BENCHMARK_TARGETS)
  add_executable(${target} ${target}.cpp)
  target_link_libraries(${target} PRIVATE wirepeek_lib benchmark::benchmark)
endforeach()

target_compile_definitions(
  bench_e2e_pcap
  PRIVATE WIREPEEK_BENCH_PCAP="${PROJECT_SOURCE_DIR}/tests/pcaps/ethernet_http_latency.pcap"
)
