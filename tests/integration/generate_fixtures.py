#!/usr/bin/env python3
"""Generate deterministic packet captures for Wirepeek integration tests."""

from pathlib import Path
import socket
import struct


PCAP_DIR = Path(__file__).resolve().parents[1] / "pcaps"
BASE_TS = 1_700_000_000
CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(payload: bytes, protocol: int, src: str, dst: str, ident: int) -> bytes:
    src_bytes = socket.inet_aton(src)
    dst_bytes = socket.inet_aton(dst)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        ident,
        0x4000,
        64,
        protocol,
        0,
        src_bytes,
        dst_bytes,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def tcp(
    payload: bytes,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
) -> bytes:
    header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        5 << 4,
        flags,
        65535,
        0,
        0,
    )
    segment = header + payload
    pseudo = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack("!BBH", 0, 6, len(segment))
    )
    value = checksum(pseudo + segment)
    return header[:16] + struct.pack("!H", value) + header[18:] + payload


def udp(payload: bytes, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack("!BBH", 0, 17, length)
    )
    value = checksum(pseudo + header + payload) or 0xFFFF
    return struct.pack("!HHHH", src_port, dst_port, length, value) + payload


def ethernet(payload: bytes, from_client: bool = True) -> bytes:
    src, dst = (
        (CLIENT_MAC, SERVER_MAC) if from_client else (SERVER_MAC, CLIENT_MAC)
    )
    return dst + src + struct.pack("!H", 0x0800) + payload


def tcp_frame(
    payload: bytes,
    from_client: bool,
    seq: int,
    ack: int,
    flags: int = 0x18,
    ident: int = 1,
) -> bytes:
    src_ip, dst_ip = (
        ("10.0.0.1", "10.0.0.2")
        if from_client
        else ("10.0.0.2", "10.0.0.1")
    )
    src_port, dst_port = (40000, 80) if from_client else (80, 40000)
    segment = tcp(payload, src_ip, dst_ip, src_port, dst_port, seq, ack, flags)
    return ethernet(ipv4(segment, 6, src_ip, dst_ip, ident), from_client)


def connection_packets(start_usec: int = 0) -> list[tuple[int, int, bytes]]:
    return [
        (BASE_TS, start_usec, tcp_frame(b"", True, 1000, 0, 0x02, 1)),
        (BASE_TS, start_usec + 50_000, tcp_frame(b"", False, 5000, 1001, 0x12, 2)),
    ]


def write_pcap(name: str, packets: list[tuple[int, int, bytes]], linktype: int = 1) -> None:
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    with (PCAP_DIR / name).open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for seconds, micros, packet in packets:
            seconds += micros // 1_000_000
            micros %= 1_000_000
            output.write(struct.pack("<IIII", seconds, micros, len(packet), len(packet)))
            output.write(packet)


def generate_latency() -> None:
    request = b"GET /latency HTTP/1.1\r\nHost: example.test\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    packets = connection_packets()
    packets.extend(
        [
            (BASE_TS, 100_000, tcp_frame(request, True, 1001, 5001, ident=3)),
            (
                BASE_TS,
                600_000,
                tcp_frame(response, False, 5001, 1001 + len(request), ident=4),
            ),
        ]
    )
    write_pcap("ethernet_http_latency.pcap", packets)


def generate_chunked() -> None:
    request1 = b"GET /chunked HTTP/1.1\r\nHost: example.test\r\n\r\n"
    response1 = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5\r\nhello\r\n0\r\n\r\n"
    )
    request2 = b"GET /second HTTP/1.1\r\nHost: example.test\r\n\r\n"
    response2 = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
    client_seq = 1001
    server_seq = 5001
    packets = connection_packets()
    packets.extend(
        [
            (BASE_TS, 100_000, tcp_frame(request1, True, client_seq, server_seq, ident=3)),
            (
                BASE_TS,
                200_000,
                tcp_frame(
                    response1,
                    False,
                    server_seq,
                    client_seq + len(request1),
                    ident=4,
                ),
            ),
            (
                BASE_TS,
                300_000,
                tcp_frame(
                    request2,
                    True,
                    client_seq + len(request1),
                    server_seq + len(response1),
                    ident=5,
                ),
            ),
            (
                BASE_TS,
                400_000,
                tcp_frame(
                    response2,
                    False,
                    server_seq + len(response1),
                    client_seq + len(request1) + len(request2),
                    ident=6,
                ),
            ),
        ]
    )
    write_pcap("ethernet_http_chunked.pcap", packets)


def generate_head() -> None:
    head = b"HEAD /resource HTTP/1.1\r\nHost: example.test\r\n\r\n"
    head_response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    get = b"GET /resource HTTP/1.1\r\nHost: example.test\r\n\r\n"
    get_response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata"
    client_seq = 1001
    server_seq = 5001
    packets = connection_packets()
    packets.extend(
        [
            (BASE_TS, 100_000, tcp_frame(head, True, client_seq, server_seq, ident=3)),
            (
                BASE_TS,
                200_000,
                tcp_frame(
                    head_response,
                    False,
                    server_seq,
                    client_seq + len(head),
                    ident=4,
                ),
            ),
            (
                BASE_TS,
                300_000,
                tcp_frame(
                    get,
                    True,
                    client_seq + len(head),
                    server_seq + len(head_response),
                    ident=5,
                ),
            ),
            (
                BASE_TS,
                400_000,
                tcp_frame(
                    get_response,
                    False,
                    server_seq + len(head_response),
                    client_seq + len(head) + len(get),
                    ident=6,
                ),
            ),
        ]
    )
    write_pcap("ethernet_http_head.pcap", packets)


def generate_dns() -> None:
    query = (
        struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        + b"\x07example\x04test\x00"
        + struct.pack("!HH", 1, 1)
    )
    datagram = udp(query, "10.0.0.1", "8.8.8.8", 53000, 53)
    packet = ethernet(ipv4(datagram, 17, "10.0.0.1", "8.8.8.8", 1))
    write_pcap("ethernet_dns.pcap", [(BASE_TS, 0, packet)])


def generate_null() -> None:
    request = b"GET /loopback HTTP/1.1\r\nHost: localhost\r\n\r\n"
    segment = tcp(request, "127.0.0.1", "127.0.0.1", 41000, 8080, 1, 1, 0x18)
    packet = struct.pack("<I", socket.AF_INET) + ipv4(
        segment, 6, "127.0.0.1", "127.0.0.1", 1
    )
    write_pcap("null_http.pcap", [(BASE_TS, 0, packet)], linktype=0)


def main() -> None:
    generate_latency()
    generate_chunked()
    generate_head()
    generate_dns()
    generate_null()
    print(f"Generated 5 fixtures in {PCAP_DIR}")


if __name__ == "__main__":
    main()
