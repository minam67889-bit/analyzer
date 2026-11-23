from __future__ import annotations

import struct

from adversarylab.capture.parsers import PacketEventParser
from adversarylab.capture.pcap import PcapWriter, open_capture
from adversarylab.core.events import EventCategory


def _eth_ip_udp(payload: bytes, sport: int = 40000, dport: int = 53) -> bytes:
    eth = bytes.fromhex("020000000002") + bytes.fromhex("020000000001") + struct.pack("!H", 0x0800)
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([10, 10, 0, 50]), bytes([10, 10, 0, 1]))
    return eth + ip + udp


def test_write_read_parse_roundtrip(tmp_path):
    from adversarylab.protocols import dns

    query = dns.DnsMessage(msg_id=11, flags=dns.FLAG_RD,
                           questions=[dns.DnsQuestion("round.lab.test", dns.TYPE_A)])
    frame = _eth_ip_udp(dns.build_message(query))
    path = tmp_path / "roundtrip.pcap"
    with PcapWriter(path) as writer:
        writer.write_raw(frame)
        writer.write_raw(frame)
    packets = list(open_capture(path))
    assert len(packets) == 2
    events = []
    for packet in packets:
        events.extend(PacketEventParser(session_id="s").parse_bytes(packet.data))
    dns_events = [e for e in events if e.category is EventCategory.DNS]
    assert len(dns_events) == 2
    assert dns_events[0].details["qname"] == "round.lab.test."


def test_pcapng_reader_detects_format(tmp_path):
    # Minimal PCAPNG: SHB + IDB + one EPB carrying an Ethernet/IPv4/UDP frame.
    frame = _eth_ip_udp(b"\x00" * 8)
    shb_body = struct.pack("<HHII", 1, 0, -1 & 0xFFFFFFFF, 0)
    shb = struct.pack("<II", 0x0A0D0D0A, 12 + len(shb_body)) + shb_body
    shb += struct.pack("<I", 12 + len(shb_body))
    idb_body = struct.pack("<HHI", 1, 0, 262144)
    idb = struct.pack("<II", 1, 12 + len(idb_body)) + idb_body
    idb += struct.pack("<I", 12 + len(idb_body))
    epb_body = struct.pack("<IIIII", 0, 0, 0, len(frame), len(frame)) + frame
    epb_body += b"\x00" * (-len(epb_body) % 4)
    epb = struct.pack("<II", 6, 12 + len(epb_body)) + epb_body
    epb += struct.pack("<I", 12 + len(epb_body))
    path = tmp_path / "ng.pcapng"
    path.write_bytes(shb + idb + epb)
    packets = list(open_capture(path))
    assert len(packets) == 1
    assert packets[0].data == frame
