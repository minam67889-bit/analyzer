"""QUIC metadata parser (header only; payload is protected)."""

from __future__ import annotations

from ...core.events import EventCategory, EventSeverity, EventSource, make_event
from ...protocols import quic
from .base import DecodedPacket


class QuicParser:
    def parse(self, packet: DecodedPacket) -> list:
        if not packet.is_udp or len(packet.payload) < 7:
            return []
        if packet.dst_port not in {443, 853, 8443} and packet.src_port not in {443, 853, 8443}:
            return []
        try:
            header = quic.parse_header(packet.payload)
        except quic.QuicError:
            return []
        return [
            make_event(
                session_id="",
                category=EventCategory.QUIC,
                source=EventSource.PACKET_CAPTURE,
                severity=EventSeverity.INFO,
                summary=(
                    f"QUIC {header.header_form} type={header.long_packet_type or '-'} "
                    f"version={header.version or '-'} (payload protected)"
                ),
                protocol="quic",
                src_addr=packet.src,
                dst_addr=packet.dst,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                details=header.to_dict(),
            )
        ]
