"""ARP / IPv6 Neighbor Discovery event parsers."""

from __future__ import annotations

from ...core.events import EventCategory, EventSeverity, EventSource, make_event
from .base import DecodedPacket

ARP_REQUEST = 1
ARP_REPLY = 2

ND_ROUTER_SOLICIT = 133
ND_ROUTER_ADVERT = 134
ND_NEIGHBOR_SOLICIT = 135
ND_NEIGHBOR_ADVERT = 136


class ArpParser:
    def parse(self, packet: DecodedPacket) -> list:
        if packet.proto != "arp":
            return []
        op = packet.details.get("arp_op")
        op_name = {ARP_REQUEST: "request", ARP_REPLY: "reply"}.get(op, str(op))
        severity = EventSeverity.NOTICE if op == ARP_REPLY else EventSeverity.INFO
        return [
            make_event(
                session_id="",
                category=EventCategory.ARP,
                source=EventSource.PACKET_CAPTURE,
                severity=severity,
                summary=f"ARP {op_name} {packet.details.get('spa')} -> {packet.details.get('tpa')}",
                protocol="arp",
                src_addr=packet.details.get("spa"),
                dst_addr=packet.details.get("tpa"),
                details=dict(packet.details),
            )
        ]


class Ipv6NeighborParser:
    def parse(self, packet: DecodedPacket) -> list:
        if packet.proto != "icmpv6":
            return []
        nd_type = packet.details.get("icmpv6_type")
        if nd_type not in {
            ND_ROUTER_SOLICIT, ND_ROUTER_ADVERT, ND_NEIGHBOR_SOLICIT, ND_NEIGHBOR_ADVERT
        }:
            return []
        names = {
            ND_ROUTER_SOLICIT: "router-solicitation",
            ND_ROUTER_ADVERT: "router-advertisement",
            ND_NEIGHBOR_SOLICIT: "neighbor-solicitation",
            ND_NEIGHBOR_ADVERT: "neighbor-advertisement",
        }
        severity = EventSeverity.NOTICE if nd_type in {ND_ROUTER_ADVERT, ND_NEIGHBOR_ADVERT} else EventSeverity.INFO
        return [
            make_event(
                session_id="",
                category=EventCategory.IPV6_NEIGHBOR,
                source=EventSource.PACKET_CAPTURE,
                severity=severity,
                summary=(
                    f"ICMPv6 {names[nd_type]} target={packet.details.get('icmpv6_target')} "
                    f"router={packet.details.get('router')} solicited={packet.details.get('solicited')}"
                ),
                protocol="icmpv6",
                src_addr=packet.src,
                dst_addr=packet.dst,
                details=dict(packet.details),
            )
        ]
