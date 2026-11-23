from __future__ import annotations

import struct

import pytest

from adversarylab.capture import link


def _mac(raw: str) -> bytes:
    return bytes.fromhex(raw.replace(":", ""))


def test_decode_ethernet_and_ipv4_udp():
    eth = _mac("02:00:00:00:00:02") + _mac("02:00:00:00:00:01") + struct.pack("!H", 0x0800)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + 8 + 4, 1, 0, 64, 17, 0,
        bytes([10, 10, 0, 50]), bytes([10, 10, 0, 1]),
    )
    udp = struct.pack("!HHHH", 40000, 53, 8 + 4, 0) + b"data"
    frame = eth + ip + udp
    decoded = link.decode_payload(1, frame)
    assert isinstance(decoded, link.EthernetFrame)
    ip_pkt = link.decode_ipv4(decoded.payload)
    assert ip_pkt.src == "10.10.0.50"
    assert ip_pkt.dst == "10.10.0.1"
    udp_pkt = link.decode_udp(ip_pkt.payload)
    assert udp_pkt.dst_port == 53
    assert udp_pkt.payload == b"data"


def test_decode_tcp_flags():
    tcp = struct.pack("!HHIIHHBBH", 1234, 443, 1, 1, (5 << 12) | 0x02, 8192, 0, 6, 0)
    decoded = link.decode_tcp(tcp)
    assert decoded.src_port == 1234
    assert decoded.dst_port == 443
    assert "SYN" in decoded.flag_names


def test_decode_arp():
    frame = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + _mac("02:00:00:00:00:01") + \
        bytes([10, 10, 0, 199]) + _mac("02:00:00:00:00:02") + bytes([10, 10, 0, 50])
    arp = link.decode_arp(frame)
    assert arp.op == 2
    assert arp.spa == "10.10.0.199"
    assert arp.tpa == "10.10.0.50"


def test_decode_ipv6_udp():
    payload = struct.pack("!HHHH", 5353, 5353, 8, 0)
    pkt = link.decode_ipv6(
        struct.pack("!IHBB", 0x60000000, len(payload), 17, 64)
        + bytes.fromhex("fd000000000000000000000000000050")
        + bytes.fromhex("fd000000000000000000000000000001")
        + payload
    )
    assert pkt.src == "fd00::50"
    assert pkt.next_header == 17


def test_decode_sll():
    sll = struct.pack("!HHH", 0, 1, 6) + _mac("02:00:00:00:00:01") + b"\x00\x00" + struct.pack("!H", 0x0800)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20, 1, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    decoded = link.decode_payload(113, sll + ip)
    assert isinstance(decoded, link.Ipv4Packet)
    assert decoded.src == "10.0.0.1"


def test_short_frame_raises():
    with pytest.raises(link.DecodeError):
        link.decode_ethernet(b"\x00" * 10)
