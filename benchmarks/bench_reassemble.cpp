#include <wirepeek/dissector/tcp_reassembler.h>
#include <wirepeek/util/spsc_queue.h>

#include <array>
#include <benchmark/benchmark.h>
#include <cstdint>
#include <vector>

namespace {

wirepeek::dissector::DissectedPacket MakePacket(uint32_t sequence,
                                                const std::vector<uint8_t>& payload) {
  using namespace wirepeek::dissector;
  DissectedPacket packet;
  packet.ip = IpInfo{
      .version = 4,
      .src_ip = Ipv4Address{192, 168, 1, 1},
      .dst_ip = Ipv4Address{10, 0, 0, 1},
      .protocol = ip_protocol::kTCP,
  };
  packet.tcp = TcpInfo{
      .src_port = 12345,
      .dst_port = 80,
      .seq_num = sequence,
      .flags = tcp_flags::kACK | tcp_flags::kPSH,
      .payload = payload,
  };
  return packet;
}

void BM_ReassembleSegments(benchmark::State& state) {
  const auto count = static_cast<size_t>(state.range(0));
  const std::vector<uint8_t> payload(128, 'x');
  std::vector<wirepeek::dissector::DissectedPacket> packets;
  packets.reserve(count);
  for (size_t i = 0; i < count; ++i) {
    packets.push_back(MakePacket(static_cast<uint32_t>(i * payload.size()), payload));
  }

  for (auto _ : state) {
    wirepeek::dissector::TcpReassembler reassembler([](const wirepeek::dissector::StreamEvent&) {});
    for (const auto& packet : packets) {
      reassembler.ProcessPacket(packet, wirepeek::Timestamp{});
    }
    benchmark::DoNotOptimize(reassembler.StreamCount());
  }
  state.SetItemsProcessed(state.iterations() * static_cast<int64_t>(count));
}

void BM_SpscRoundTrip(benchmark::State& state) {
  wirepeek::util::SpscQueue<uint64_t, 1024> queue;
  uint64_t value = 0;
  for (auto _ : state) {
    benchmark::DoNotOptimize(queue.TryPush(value++));
    benchmark::DoNotOptimize(queue.TryPop());
  }
}

BENCHMARK(BM_ReassembleSegments)->Arg(1)->Arg(16)->Arg(256);
BENCHMARK(BM_SpscRoundTrip);

}  // namespace

BENCHMARK_MAIN();
