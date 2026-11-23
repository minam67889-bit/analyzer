"""DNS event parser."""

from __future__ import annotations

from ...core.events import EventCategory, EventSeverity, EventSource, make_event
from ...protocols import dns
from .base import DecodedPacket


class DnsParser:
    def parse(self, packet: DecodedPacket) -> list:
        if not packet.is_udp and not packet.is_tcp:
            return []
        if packet.src_port != 53 and packet.dst_port != 53:
            return []
        if not packet.payload:
            return []
        try:
            msg = dns.parse_message(packet.payload)
        except dns.DnsError:
            return []
        if not msg.questions:
            return []
        question = msg.questions[0]
        base = {
            "session_id": "",
            "category": EventCategory.DNS,
            "source": EventSource.PACKET_CAPTURE,
            "protocol": "dns",
            "src_addr": packet.src,
            "dst_addr": packet.dst,
            "src_port": packet.src_port,
            "dst_port": packet.dst_port,
        }
        details = {
            "qname": question.name,
            "qtype": question.qtype,
            "qclass": question.qclass,
            "msg_id": msg.msg_id,
            "rcode": msg.rcode,
            "aa": bool(msg.flags & dns.FLAG_AA),
            "ra": bool(msg.flags & dns.FLAG_RA),
            "is_response": msg.is_response,
        }
        answers = []
        for rr in msg.answers:
            answers.append(
                {
                    "name": rr.name,
                    "type": rr.rtype,
                    "ttl": rr.ttl,
                    "address": rr.address,
                    "cname": rr.cname,
                    "text": rr.text,
                }
            )
        details["answers"] = answers
        severity = EventSeverity.INFO
        if msg.rcode == dns.RCODE_NXDOMAIN:
            severity = EventSeverity.NOTICE
        return [
            make_event(
                severity=severity,
                summary=(
                    f"DNS {'response' if msg.is_response else 'query'} "
                    f"{question.name} type={question.qtype} rcode={msg.rcode}"
                ),
                details=details,
                **base,
            )
        ]
