from __future__ import annotations

import struct

from adversarylab.capture.parsers import PacketEventParser
from adversarylab.protocols import dns


def _mac(raw: str) -> bytes:
    return bytes.fromhex(raw.replace(":", ""))


def _ip_udp_frame(payload: bytes, src="10.10.0.50", dst="10.10.0.1", sport=40000, dport=53) -> bytes:
    eth = _mac("02:00:00:00:00:02") + _mac("02:00:00:00:00:01") + struct.pack("!H", 0x0800)
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
        bytes(int(x) for x in src.split(".")), bytes(int(x) for x in dst.split(".")),
    )
    return eth + ip + udp


def test_dns_parser():
    query = dns.DnsMessage(msg_id=7, flags=dns.FLAG_RD,
                           questions=[dns.DnsQuestion("api.lab.test", dns.TYPE_A)])
    frame = _ip_udp_frame(dns.build_message(query))
    events = PacketEventParser(session_id="s1").parse_bytes(frame)
    dns_events = [e for e in events if e.category.value == "dns"]
    assert dns_events
    assert dns_events[0].details["qname"] == "api.lab.test."
    assert dns_events[0].src_addr == "10.10.0.50"
    assert dns_events[0].dst_port == 53


def test_arp_parser():
    eth = _mac("02:00:00:00:00:02") + _mac("02:00:00:00:00:01") + struct.pack("!H", 0x0806)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + _mac("02:00:00:00:00:01") + \
        bytes([10, 10, 0, 199]) + _mac("02:00:00:00:00:02") + bytes([10, 10, 0, 50])
    events = PacketEventParser(session_id="s1").parse_bytes(eth + arp)
    arp_events = [e for e in events if e.category.value == "arp"]
    assert len(arp_events) == 1
    assert arp_events[0].details["spa"] == "10.10.0.199"


def test_http_parser():
    request = b"GET /index.html HTTP/1.1\r\nHost: plain.lab.test\r\nUser-Agent: test\r\n\r\n"
    # Build a TCP frame carrying the request
    eth = _mac("02:00:00:00:00:02") + _mac("02:00:00:00:00:01") + struct.pack("!H", 0x0800)
    tcp = struct.pack("!HHIIHHBBH", 50000, 80, 1, 1, (5 << 12) | 0x18, 8192, 0, 6, 0) + request
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     bytes([10, 10, 0, 50]), bytes([10, 10, 0, 1]))
    events = PacketEventParser(session_id="s1").parse_bytes(eth + ip + tcp)
    http_events = [e for e in events if e.category.value == "http"]
    assert http_events
    assert http_events[0].details["host"] == "plain.lab.test"
    assert http_events[0].details["method"] == "GET"


def test_parser_ignores_malformed():
    events = PacketEventParser(session_id="s1").parse_bytes(b"\x00\x01\x02")
    assert events == []
