#!/usr/bin/env bash
set -euo pipefail

: "${WIREPEEK_BIN:?WIREPEEK_BIN must point to the wirepeek executable}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PCAP_DIR="${SCRIPT_DIR}/../pcaps"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

run_fixture() {
  local fixture="$1"
  local count="$2"
  shift 2

  local output="${TMP_DIR}/${fixture}.log"
  "${WIREPEEK_BIN}" --headless --read "${PCAP_DIR}/${fixture}" -c "${count}" \
    >"${output}" 2>&1

  local pattern
  for pattern in "$@"; do
    if ! grep -Fq -- "${pattern}" "${output}"; then
      echo "Missing '${pattern}' in output for ${fixture}" >&2
      cat "${output}" >&2
      return 1
    fi
  done
}

run_fixture ethernet_http_latency.pcap 4 "TCP" "GET /latency" "200 OK (500ms)" "4 packets captured"
run_fixture ethernet_http_chunked.pcap 6 "TCP" "GET /chunked" "GET /second" "6 packets captured"
run_fixture ethernet_http_head.pcap 6 "TCP" "HEAD /resource" "GET /resource" "6 packets captured"
run_fixture ethernet_dns.pcap 1 "UDP" "1 packets captured"
run_fixture null_http.pcap 1 "127.0.0.1:41000" "TCP" "1 packets captured"

echo "CLI pcap integration scaffolding passed"
