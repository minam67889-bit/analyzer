"""Classic PCAP and PCAPNG readers plus a classic PCAP writer.

Implemented in pure Python so evidence can be read, validated and exported on any host
without Npcap/WinPcap. Live capture on Windows uses Npcap through the capture source
abstraction; this module handles recorded evidence and offline replay.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113
LINKTYPE_RAW_IP = 101
LINKTYPE_IEEE802_11 = 105
LINKTYPE_RADIOTAP = 127
LINKTYPE_NULL = 0

_PCAP_MAGIC_BE = 0xA1B2C3D4
_PCAP_MAGIC_LE = 0xD4C3B2A1
_PCAP_NANO_BE = 0xA1B23C4D
_PCAP_NANO_LE = 0x4D3CB2A1

_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_IDB = 0x00000001
_PCAPNG_EPB = 0x00000006
_PCAPNG_SPB = 0x00000003


class PcapError(ValueError):
    pass


@dataclass(frozen=True)
class RawPacket:
    linktype: int
    timestamp: datetime
    data: bytes
    original_length: int | None = None


def _datetime_from_parts(sec: int, frac: int, nano: bool) -> datetime:
    microseconds = frac // 1000 if nano else frac
    if microseconds >= 1_000_000:
        sec += microseconds // 1_000_000
        microseconds %= 1_000_000
    return datetime.fromtimestamp(sec, tz=UTC).replace(microsecond=microseconds)


class PcapReader:
    """Read a classic PCAP file. Use :func:`open_capture` for auto-detection."""

    def __init__(self, source: str | Path | bytes) -> None:
        if isinstance(source, str | Path):
            self._data = Path(source).read_bytes()
        else:
            self._data = source
        if len(self._data) < 24:
            raise PcapError("file too short for a PCAP global header")
        magic = struct.unpack("!I", self._data[:4])[0]
        if magic in (_PCAP_MAGIC_BE, _PCAP_NANO_BE):
            self._endian = ">"
            self._nano = magic == _PCAP_NANO_BE
        elif magic in (_PCAP_MAGIC_LE, _PCAP_NANO_LE):
            self._endian = "<"
            self._nano = magic == _PCAP_NANO_LE
        else:
            raise PcapError(f"not a classic PCAP file (magic {magic:#x})")
        self.linktype = struct.unpack(f"{self._endian}I", self._data[20:24])[0]
        self._pos = 24

    def __iter__(self) -> Iterator[RawPacket]:
        data = self._data
        while self._pos + 16 <= len(data):
            sec, frac, incl_len, orig_len = struct.unpack(
                f"{self._endian}IIII", data[self._pos : self._pos + 16]
            )
            self._pos += 16
            if self._pos + incl_len > len(data):
                break
            payload = data[self._pos : self._pos + incl_len]
            self._pos += incl_len
            yield RawPacket(
                linktype=self.linktype,
                timestamp=_datetime_from_parts(sec, frac, self._nano),
                data=payload,
                original_length=orig_len,
            )


class PcapngReader:
    """Read PCAPNG, including enhanced/simple packet blocks and multiple interfaces."""

    def __init__(self, source: str | Path | bytes) -> None:
        if isinstance(source, str | Path):
            self._data = Path(source).read_bytes()
        else:
            self._data = source
        self._linktypes: list[int] = []
        if len(self._data) < 12:
            raise PcapError("file too short for PCAPNG")
        first = struct.unpack("!I", self._data[:4])[0]
        if first != _PCAPNG_SHB:
            raise PcapError("not a PCAPNG file")
        # Determine endianness from the SHB byte-order magic.
        bom = self._data[8:12]
        self._endian = ">" if bom == b"\x1a\x2b\x3c\x4d" else "<"

    def __iter__(self) -> Iterator[RawPacket]:
        data = self._data
        pos = 0
        while pos + 12 <= len(data):
            block_type = struct.unpack(f"{self._endian}I", data[pos : pos + 4])[0]
            block_len = struct.unpack(f"{self._endian}I", data[pos + 4 : pos + 8])[0]
            if block_len < 12 or pos + block_len > len(data):
                break
            body = data[pos + 8 : pos + block_len - 4]
            if block_type == _PCAPNG_SHB:
                self._linktypes = []
            elif block_type == _PCAPNG_IDB:
                if len(body) >= 2:
                    self._linktypes.append(struct.unpack(f"{self._endian}H", body[:2])[0])
            elif block_type == _PCAPNG_EPB:
                if len(body) >= 20 and self._linktypes:
                    iface, ts_high, ts_low, caplen = struct.unpack(
                        f"{self._endian}IIII", body[:16]
                    )
                    payload = body[20 : 20 + caplen]
                    ts = (ts_high << 32) | ts_low
                    # Resolution defaults to microseconds unless an if_tsresol option says
                    # otherwise; we use microseconds, which covers the common case.
                    yield RawPacket(
                        linktype=self._linktypes[min(iface, len(self._linktypes) - 1)],
                        timestamp=_datetime_from_parts(ts // 1_000_000, ts % 1_000_000, False),
                        data=payload,
                        original_length=struct.unpack(f"{self._endian}I", body[16:20])[0],
                    )
            elif block_type == _PCAPNG_SPB:
                if len(body) >= 4 and self._linktypes:
                    orig_len = struct.unpack(f"{self._endian}I", body[:4])[0]
                    payload = body[4 : 4 + orig_len]
                    yield RawPacket(
                        linktype=self._linktypes[0],
                        timestamp=datetime.now(UTC),
                        data=payload,
                        original_length=orig_len,
                    )
            pos += block_len


def open_capture(source: str | Path | bytes) -> Iterator[RawPacket]:
    """Auto-detect classic PCAP vs PCAPNG and yield packets."""
    if isinstance(source, str | Path):
        head = Path(source).read_bytes()[:4]
    else:
        head = source[:4]
    if len(head) >= 4 and struct.unpack("!I", head)[0] == _PCAPNG_SHB:
        yield from PcapngReader(source)
    else:
        yield from PcapReader(source)


class PcapWriter:
    """Classic PCAP writer (little-endian, microsecond resolution)."""

    def __init__(self, path: str | Path, linktype: int = LINKTYPE_ETHERNET, snaplen: int = 262144) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.linktype = linktype
        self._fh = self.path.open("wb")
        # Write the standard magic in little-endian byte order (bytes d4 c3 b2 a1).
        self._fh.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))

    def write(self, packet: RawPacket, timestamp: datetime | None = None) -> None:
        ts = timestamp or packet.timestamp
        sec = int(ts.timestamp())
        micros = ts.microsecond
        data = packet.data
        self._fh.write(struct.pack("<IIII", sec, micros, len(data), packet.original_length or len(data)))
        self._fh.write(data)

    def write_raw(self, data: bytes, timestamp: datetime | None = None,
                  linktype: int | None = None, original_length: int | None = None) -> None:
        self.write(
            RawPacket(
                linktype=linktype or self.linktype,
                timestamp=timestamp or datetime.now(UTC),
                data=data,
                original_length=original_length,
            )
        )

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> PcapWriter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def write_packets(path: str | Path, packets: Iterator[RawPacket], linktype: int) -> int:
    count = 0
    with PcapWriter(path, linktype=linktype) as writer:
        for packet in packets:
            writer.write(packet)
            count += 1
    return count
