"""Packet decoding context and parser interfaces."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from ...core.events import NetworkEvent
from ..link import (
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    IPPROTO_ICMP,
    IPPROTO_ICMPV6,
    IPPROTO_TCP,
    IPPROTO_UDP,
    decode_arp,
    decode_ethernet,
    decode_icmpv4,
    decode_icmpv6_neighbor,
    decode_ipv4,
    decode_ipv6,
    decode_tcp,
    decode_udp,
)
from ..pcap import RawPacket


@dataclass
class DecodedPacket:
    raw: RawPacket
    timestamp: datetime
    linktype: int
    src: str | None = None
    dst: str | None = None
    proto: str | None = None
    ip_proto: int | None = None
    src_port: int | None = None
    dst_port: int | None = None
    payload: bytes = b""
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def is_tcp(self) -> bool:
        return self.proto == "tcp"

    @property
    def is_udp(self) -> bool:
        return self.proto == "udp"


class PacketParser(Protocol):
    def parse(self, packet: DecodedPacket) -> list[NetworkEvent]: ...


def decode_packet(raw: RawPacket) -> DecodedPacket:
    data = raw.data
    decoded = DecodedPacket(raw=raw, timestamp=raw.timestamp, linktype=raw.linktype)

    if raw.linktype == 1:  # Ethernet
        eth = decode_ethernet(data)
        if eth.ethertype == ETHERTYPE_ARP:
            arp = decode_arp(eth.payload)
            decoded.proto = "arp"
            decoded.details = {
                "arp_op": arp.op, "sha": arp.sha, "spa": arp.spa,
                "tha": arp.tha, "tpa": arp.tpa,
            }
            decoded.src = arp.spa
            decoded.dst = arp.tpa
            return decoded
        if eth.ethertype == ETHERTYPE_IPV4:
            _fill_ipv4(decoded, decode_ipv4(eth.payload))
            return decoded
        if eth.ethertype == ETHERTYPE_IPV6:
            _fill_ipv6(decoded, decode_ipv6(eth.payload))
            return decoded
        decoded.payload = eth.payload
        return decoded

    if raw.linktype in (101, 12):
        version = data[0] >> 4 if data else 4
        if version == 6:
            _fill_ipv6(decoded, decode_ipv6(data))
        else:
            _fill_ipv4(decoded, decode_ipv4(data))
        return decoded

    if raw.linktype == 113:
        if len(data) < 16:
            return decoded
        import struct

        proto = struct.unpack("!H", data[14:16])[0]
        payload = data[16:]
        if proto == ETHERTYPE_ARP:
            arp = decode_arp(payload)
            decoded.proto = "arp"
            decoded.details = {"arp_op": arp.op, "spa": arp.spa, "tpa": arp.tpa}
            decoded.src, decoded.dst = arp.spa, arp.tpa
            return decoded
        if proto == ETHERTYPE_IPV4:
            _fill_ipv4(decoded, decode_ipv4(payload))
            return decoded
        if proto == ETHERTYPE_IPV6:
            _fill_ipv6(decoded, decode_ipv6(payload))
            return decoded
        return decoded

    # Radiotap / raw 802.11 / unknown: leave raw.
    decoded.payload = data
    return decoded


def _fill_ipv4(decoded: DecodedPacket, ip) -> None:
    decoded.src = ip.src
    decoded.dst = ip.dst
    decoded.ip_proto = ip.proto
    decoded.details["ttl"] = ip.ttl
    if ip.proto == IPPROTO_TCP:
        tcp = decode_tcp(ip.payload)
        decoded.proto = "tcp"
        decoded.src_port = tcp.src_port
        decoded.dst_port = tcp.dst_port
        decoded.payload = tcp.payload
        decoded.details["tcp_flags"] = tcp.flag_names
        decoded.details["seq"] = tcp.seq
        decoded.details["ack"] = tcp.ack
    elif ip.proto == IPPROTO_UDP:
        udp = decode_udp(ip.payload)
        decoded.proto = "udp"
        decoded.src_port = udp.src_port
        decoded.dst_port = udp.dst_port
        decoded.payload = udp.payload
    elif ip.proto == IPPROTO_ICMP:
        decoded.proto = "icmp"
        icmp = decode_icmpv4(ip.payload)
        decoded.details["icmp_type"] = icmp.type
        decoded.details["icmp_code"] = icmp.code
        decoded.payload = icmp.payload


def _fill_ipv6(decoded: DecodedPacket, ip) -> None:
    decoded.src = ip.src
    decoded.dst = ip.dst
    decoded.ip_proto = ip.next_header
    decoded.details["hop_limit"] = ip.hop_limit
    if ip.next_header == IPPROTO_TCP:
        tcp = decode_tcp(ip.payload)
        decoded.proto = "tcp"
        decoded.src_port = tcp.src_port
        decoded.dst_port = tcp.dst_port
        decoded.payload = tcp.payload
        decoded.details["tcp_flags"] = tcp.flag_names
    elif ip.next_header == IPPROTO_UDP:
        udp = decode_udp(ip.payload)
        decoded.proto = "udp"
        decoded.src_port = udp.src_port
        decoded.dst_port = udp.dst_port
        decoded.payload = udp.payload
    elif ip.next_header == IPPROTO_ICMPV6:
        decoded.proto = "icmpv6"
        nd = decode_icmpv6_neighbor(ip.payload)
        decoded.details.update(
            {
                "icmpv6_type": nd.type,
                "icmpv6_target": nd.target,
                "router": nd.router,
                "solicited": nd.solicited,
                "override": nd.override,
            }
        )
        decoded.payload = nd.payload
