from __future__ import annotations

import struct
from datetime import UTC, datetime

from adversarylab.capture.pcap import (
    LINKTYPE_ETHERNET,
    PcapngReader,
    PcapReader,
    PcapWriter,
    RawPacket,
    open_capture,
)


def test_classic_pcap_roundtrip(tmp_path):
    packets = [
        RawPacket(LINKTYPE_ETHERNET, datetime(2026, 1, 1, tzinfo=UTC), b"\x01" * 20),
        RawPacket(LINKTYPE_ETHERNET, datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC), b"\x02" * 30),
    ]
    path = tmp_path / "test.pcap"
    with PcapWriter(path) as writer:
        for packet in packets:
            writer.write(packet)
    read = list(PcapReader(path))
    assert len(read) == 2
    assert read[0].data == b"\x01" * 20
    assert read[1].timestamp.second == 1


def test_open_capture_auto_detect(tmp_path):
    path = tmp_path / "auto.pcap"
    with PcapWriter(path) as writer:
        writer.write_raw(b"\xaa" * 10)
    packets = list(open_capture(path))
    assert len(packets) == 1
    assert packets[0].linktype == LINKTYPE_ETHERNET


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    total = 12 + len(body)
    return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)


def _pcapng_bytes() -> bytes:
    shb = _pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = _pcapng_block(0x00000001, struct.pack("<HHI", LINKTYPE_ETHERNET, 0, 262144))
    payload = b"\xbb" * 24
    epb_body = struct.pack("<IIIII", 0, 0, 0, len(payload), len(payload)) + payload
    epb = _pcapng_block(0x00000006, epb_body)
    return shb + idb + epb


def test_pcapng_reader():
    packets = list(PcapngReader(_pcapng_bytes()))
    assert len(packets) == 1
    assert packets[0].linktype == LINKTYPE_ETHERNET
    assert packets[0].data == b"\xbb" * 24


def test_pcapng_auto_detect(tmp_path):
    path = tmp_path / "test.pcapng"
    path.write_bytes(_pcapng_bytes())
    packets = list(open_capture(path))
    assert len(packets) == 1
