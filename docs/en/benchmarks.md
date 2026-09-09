# Benchmarks

Wirepeek's microbenchmarks use [Google Benchmark](https://github.com/google/benchmark).
They cover packet dissection, TCP reassembly, HTTP/1 parsing, the SPSC queue, and
end-to-end reading of the bundled latency pcap.

Configure and build them separately from the default developer build:

```sh
cmake -S . -B build-bench \
  -DCMAKE_BUILD_TYPE=Release \
  -DWIREPEEK_BUILD_BENCHMARKS=ON
cmake --build build-bench -j8
```

Run all benchmark executables:

```sh
for bench in dissect reassemble http1 e2e_pcap; do
  "./build-bench/benchmarks/bench_${bench}" --benchmark_min_time=1s
done
```

Google Benchmark reports wall-clock and CPU time in ns/op by default. Compare
results on the same machine, build type, compiler, and power profile. The
end-to-end pcap benchmark skips itself if its fixture is unavailable.
