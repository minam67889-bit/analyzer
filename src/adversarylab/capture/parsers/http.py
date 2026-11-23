"""HTTP/1.x metadata parser (headers only; bodies are not inspected)."""

from __future__ import annotations

from ...core.events import EventCategory, EventSeverity, EventSource, make_event
from ...protocols import http
from .base import DecodedPacket

_METHODS = {
    b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ",
    b"PATCH ", b"CONNECT ", b"TRACE ",
}

_INTERESTING_HEADERS = (
    "host", "user-agent", "content-length", "connection", "upgrade",
    "authorization", "cookie", "referer", "origin", "accept", "cache-control",
)


class HttpParser:
    def parse(self, packet: DecodedPacket) -> list:
        if not packet.is_tcp or not packet.payload:
            return []
        head = packet.payload[:16]
        is_request = any(head.startswith(m) for m in _METHODS)
        is_response = head.startswith(b"HTTP/")
        if not (is_request or is_response):
            return []
        try:
            if is_request:
                request = http.parse_request(packet.payload)
                details = request.to_dict()
                details["direction"] = "request"
                summary = f"HTTP {request.method} {request.target} host={request.headers.get('host', '-')}"
            else:
                response = http.parse_response(packet.payload)
                details = response.to_dict()
                details["direction"] = "response"
                summary = f"HTTP {response.status} {response.reason}".rstrip()
        except http.HttpError:
            return []
        details["headers"] = {k: details["headers"][k] for k in _INTERESTING_HEADERS if k in details["headers"]}
        if details.get("direction") == "request":
            details["host"] = details["headers"].get("host")
        return [
            make_event(
                session_id="",
                category=EventCategory.HTTP,
                source=EventSource.PACKET_CAPTURE,
                severity=EventSeverity.INFO,
                summary=summary,
                protocol="http",
                src_addr=packet.src,
                dst_addr=packet.dst,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                details=details,
            )
        ]
