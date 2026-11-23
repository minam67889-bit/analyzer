"""Composite packet parser producing normalized events."""

from __future__ import annotations

from datetime import UTC, datetime

from ...core.events import EventCategory, EventSeverity, EventSource, make_event
from ..link import DecodeError
from ..pcap import RawPacket
from .arp import ArpParser, Ipv6NeighborParser
from .base import DecodedPacket, PacketParser, decode_packet
from .dhcp import DhcpParser
from .dns import DnsParser
from .http import HttpParser
from .quic import QuicParser
from .tls import TlsParser

_DEFAULT_PARSERS = (DnsParser(), DhcpParser(), ArpParser(), Ipv6NeighborParser(),
                   TlsParser(), HttpParser(), QuicParser())


class PacketEventParser:
    """Decode raw packets into :class:`NetworkEvent` objects."""

    def __init__(self, parsers: list[PacketParser] | None = None, session_id: str = "") -> None:
        self.parsers = parsers if parsers is not None else list(_DEFAULT_PARSERS)
        self.session_id = session_id

    def parse_raw(self, raw: RawPacket) -> list:
        try:
            decoded = decode_packet(raw)
        except (DecodeError, ValueError):
            return []
        events = []
        for parser in self.parsers:
            try:
                for event in parser.parse(decoded):
                    events.append(_retarget(event, self.session_id))
            except Exception:  # a parser must never break the pipeline
                continue
        return events

    def parse_bytes(self, data: bytes, *, linktype: int = 1, timestamp=None) -> list:
        raw = RawPacket(
            linktype=linktype,
            timestamp=timestamp or datetime.now(UTC),
            data=data,
        )
        return self.parse_raw(raw)


def _retarget(event, session_id: str):
    from dataclasses import replace

    if not session_id:
        return event
    return replace(event, session_id=session_id)


def make_connection_event(
    *,
    session_id: str,
    src: str | None,
    dst: str | None,
    src_port: int | None,
    dst_port: int | None,
    protocol: str | None,
    flags: list[str] | None = None,
    summary: str = "",
):
    return make_event(
        session_id=session_id,
        category=EventCategory.CONNECTION,
        source=EventSource.PACKET_CAPTURE,
        severity=EventSeverity.DEBUG,
        summary=summary or f"{protocol} {src}:{src_port} -> {dst}:{dst_port}",
        protocol=protocol,
        src_addr=src,
        dst_addr=dst,
        src_port=src_port,
        dst_port=dst_port,
        details={"tcp_flags": flags or []},
    )


__all__ = [
    "PacketEventParser",
    "DecodedPacket",
    "PacketParser",
    "decode_packet",
    "DnsParser",
    "DhcpParser",
    "ArpParser",
    "Ipv6NeighborParser",
    "TlsParser",
    "HttpParser",
    "QuicParser",
    "make_connection_event",
]
