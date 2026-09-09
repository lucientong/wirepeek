#!/usr/bin/env python3
"""Generate small libFuzzer corpora from the unit-test fixtures."""

from pathlib import Path


ROOT = Path(__file__).parent / "corpus"


def write(target: str, name: str, data: bytes) -> None:
    directory = ROOT / target
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(data)


ethernet = bytes.fromhex("00112233445566778899aabb0800dead")
ipv4 = bytes.fromhex("450000164000400040060000c0a801010a0000010102")
ipv6 = bytes.fromhex(
    "6000000000020640"
    "00000000000000000000000000000001"
    "00000000000000000000000000000002"
    "0102"
)
tcp = bytes.fromhex("3039005000000001000000005002ffff00000000")
udp = bytes.fromhex("30390035000a0000abcd")
dns_query = (
    bytes.fromhex("123401000001000000000000")
    + b"\x07example\x03com\x00"
    + bytes.fromhex("00010001")
)
dns_response = (
    bytes.fromhex("123481800001000100000000")
    + b"\x07example\x03com\x00"
    + bytes.fromhex("00010001c00c000100010000003c0004")
    + bytes((93, 184, 216, 34))
)
tls_server_hello = (
    bytes.fromhex("160303002a020000260303")
    + b"\xbb" * 32
    + bytes.fromhex("00c02f00")
)

write("ethernet", "ipv4_frame", ethernet)
write("ethernet", "vlan_frame", ethernet[:12] + bytes.fromhex("810000640800cafe"))
write("ip", "ipv4", ipv4)
write("ip", "ipv6", ipv6)
write("tcp", "syn", tcp)
write("tcp", "http_data", tcp[:13] + b"\x18" + tcp[14:] + b"GET / HTTP/1.1\r\n\r\n")
write("udp", "dns_datagram", udp)
write("udp", "empty_datagram", bytes.fromhex("03e807d000080000"))
write("dns", "query", dns_query)
write("dns", "response", dns_response)
write("tls", "server_hello", tls_server_hello)
write("tls", "truncated_record", bytes.fromhex("16030100"))
write("websocket", "text_frame", b"\x81\x05hello")
write("websocket", "masked_frame", bytes.fromhex("828300000000010203"))
write("http1", "request", b"\x00GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
write("http1", "response", b"\x01HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
