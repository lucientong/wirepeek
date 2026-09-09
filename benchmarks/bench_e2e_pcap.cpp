#include <wirepeek/capture/file_source.h>
#include <wirepeek/dissector/dissect.h>

#include <benchmark/benchmark.h>
#include <filesystem>

namespace {

void BM_ReadAndDissectPcap(benchmark::State& state) {
  const std::filesystem::path pcap = WIREPEEK_BENCH_PCAP;
  if (!std::filesystem::exists(pcap)) {
    state.SkipWithError("benchmark pcap fixture is unavailable");
    return;
  }

  for (auto _ : state) {
    wirepeek::capture::FileSource source(pcap.string());
    size_t packets = 0;
    source.Start([&packets](const wirepeek::PacketView& packet) {
      benchmark::DoNotOptimize(wirepeek::dissector::Dissect(packet));
      ++packets;
    });
    benchmark::DoNotOptimize(packets);
  }
}

BENCHMARK(BM_ReadAndDissectPcap);

}  // namespace

BENCHMARK_MAIN();
