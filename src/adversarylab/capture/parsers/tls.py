"""TLS handshake metadata parser (no decryption)."""

from __future__ import annotations

from ...core.events import EventCategory, EventSeverity, EventSource, make_event
from ...protocols import tls
from .base import DecodedPacket

_TLS_PORTS = {443, 8443, 4433, 9443, 853, 465, 587, 636, 993, 995, 8883}


class TlsParser:
    def parse(self, packet: DecodedPacket) -> list:
        if not packet.is_tcp or not packet.payload:
            return []
        port_hint = packet.dst_port in _TLS_PORTS or packet.src_port in _TLS_PORTS
        looks_like_tls = (
            len(packet.payload) >= 5
            and packet.payload[0] == 0x16
            and packet.payload[1] == 0x03
        )
        if not (port_hint or looks_like_tls):
            return []
        try:
            hello = tls.parse_client_hello(packet.payload)
        except tls.TlsError:
            return []
        severity = EventSeverity.INFO if hello.sni else EventSeverity.NOTICE
        return [
            make_event(
                session_id="",
                category=EventCategory.TLS,
                source=EventSource.PACKET_CAPTURE,
                severity=severity,
                summary=(
                    f"TLS ClientHello sni={hello.sni or '-'} "
                    f"alpn={','.join(hello.alpn) or '-'} ja3={hello.ja3_md5}"
                ),
                protocol="tls",
                src_addr=packet.src,
                dst_addr=packet.dst,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                details=hello.to_dict(),
            )
        ]
