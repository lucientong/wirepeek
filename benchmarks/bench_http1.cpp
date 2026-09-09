#include <wirepeek/protocol/http1.h>

#include <benchmark/benchmark.h>
#include <cstdint>
#include <span>
#include <string_view>

namespace {

std::span<const uint8_t> AsBytes(std::string_view text) {
  return {reinterpret_cast<const uint8_t*>(text.data()), text.size()};
}

void BM_Http1RequestResponse(benchmark::State& state) {
  constexpr std::string_view request =
      "GET /api/items HTTP/1.1\r\nHost: example.com\r\nAccept: application/json\r\n\r\n";
  constexpr std::string_view response =
      "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n"
      "{\"ok\":true}";

  for (auto _ : state) {
    wirepeek::protocol::Http1Parser parser([](const wirepeek::HttpTransaction& transaction) {
      benchmark::DoNotOptimize(transaction);
    });
    parser.Feed(AsBytes(request), wirepeek::StreamDirection::kClientToServer,
                wirepeek::Timestamp{});
    parser.Feed(AsBytes(response), wirepeek::StreamDirection::kServerToClient,
                wirepeek::Timestamp{});
  }
}

BENCHMARK(BM_Http1RequestResponse);

}  // namespace

BENCHMARK_MAIN();
