"""Link/network/transport header decoders.

Pure-Python and dependency-free so synthetic packets can be built and asserted in unit
tests. These decoders intentionally do not verify checksums; the laboratory is interested
in metadata, not forwarding correctness.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from typing import Any

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58
IPPROTO_HOPOPT = 0
IPPROTO_ROUTING = 43
IPPROTO_FRAGMENT = 44
IPPROTO_AH = 51
IPPROTO_ESP = 50

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80


class DecodeError(ValueError):
    pass


@dataclass
class EthernetFrame:
    dst: str
    src: str
    ethertype: int
    payload: bytes
    vlan: int | None = None


@dataclass
class ArpFrame:
    op: int
    sha: str
    spa: str
    tha: str
    tpa: str


@dataclass
class Ipv4Packet:
    src: str
    dst: str
    proto: int
    ttl: int
    identification: int
    flags: int
    frag_offset: int
    payload: bytes
    header_length: int
    total_length: int
    tos: int = 0


@dataclass
class Ipv6Packet:
    src: str
    dst: str
    next_header: int
    hop_limit: int
    payload: bytes
    traffic_class: int = 0
    flow_label: int = 0


@dataclass
class TcpSegment:
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    window: int
    payload: bytes
    data_offset: int
    urg: int = 0

    @property
    def flag_names(self) -> list[str]:
        names = []
        for bit, name in (
            (TCP_FIN, "FIN"), (TCP_SYN, "SYN"), (TCP_RST, "RST"),
            (TCP_PSH, "PSH"), (TCP_ACK, "ACK"), (TCP_URG, "URG"),
            (TCP_ECE, "ECE"), (TCP_CWR, "CWR"),
        ):
            if self.flags & bit:
                names.append(name)
        return names


@dataclass
class UdpDatagram:
    src_port: int
    dst_port: int
    length: int
    payload: bytes


@dataclass
class Icmpv4Message:
    type: int
    code: int
    payload: bytes


@dataclass
class Icmpv6NeighborMessage:
    type: int
    code: int
    target: str | None = None
    source_link_layer: str | None = None
    target_link_layer: str | None = None
    router: bool = False
    solicited: bool = False
    override: bool = False
    payload: bytes = b""


def decode_ethernet(data: bytes) -> EthernetFrame:
    if len(data) < 14:
        raise DecodeError("short Ethernet frame")
    dst = _mac(data[0:6])
    src = _mac(data[6:12])
    ethertype = struct.unpack("!H", data[12:14])[0]
    payload = data[14:]
    vlan = None
    while ethertype in (ETHERTYPE_VLAN, 0x88A8):
        if len(payload) < 4:
            raise DecodeError("short VLAN tag")
        tci = struct.unpack("!H", payload[:2])[0]
        vlan = tci & 0x0FFF
        ethertype = struct.unpack("!H", payload[2:4])[0]
        payload = payload[4:]
    return EthernetFrame(dst=dst, src=src, ethertype=ethertype, payload=payload, vlan=vlan)


def decode_arp(data: bytes) -> ArpFrame:
    if len(data) < 28:
        raise DecodeError("short ARP frame")
    htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", data[:8])
    if ptype != ETHERTYPE_IPV4 or plen != 4:
        raise DecodeError("unsupported ARP protocol")
    sha = _mac(data[8 : 8 + hlen])
    spa = str(ipaddress.ip_address(data[8 + hlen : 8 + hlen + 4]))
    tha = _mac(data[8 + hlen + 4 : 8 + hlen + 4 + hlen])
    tpa = str(ipaddress.ip_address(data[8 + hlen + 4 + hlen : 8 + hlen + 4 + hlen + 4]))
    return ArpFrame(op=op, sha=sha, spa=spa, tha=tha, tpa=tpa)


def decode_ipv4(data: bytes) -> Ipv4Packet:
    if len(data) < 20:
        raise DecodeError("short IPv4 header")
    version_ihl = data[0]
    if version_ihl >> 4 != 4:
        raise DecodeError("not IPv4")
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        raise DecodeError("bad IPv4 IHL")
    tos, total_length, ident, flags_frag, ttl, proto, _checksum = struct.unpack(
        "!BHHHBBH", data[1:12]
    )
    src = str(ipaddress.ip_address(data[12:16]))
    dst = str(ipaddress.ip_address(data[16:20]))
    flags = (flags_frag >> 13) & 0x7
    frag_offset = flags_frag & 0x1FFF
    payload = data[ihl:total_length]
    return Ipv4Packet(
        src=src, dst=dst, proto=proto, ttl=ttl, identification=ident,
        flags=flags, frag_offset=frag_offset, payload=payload,
        header_length=ihl, total_length=total_length, tos=tos,
    )


def decode_ipv6(data: bytes) -> Ipv6Packet:
    if len(data) < 40:
        raise DecodeError("short IPv6 header")
    if data[0] >> 4 != 6:
        raise DecodeError("not IPv6")
    traffic = ((data[0] & 0x0F) << 4) | (data[1] >> 4)
    flow = ((data[1] & 0x0F) << 16) | struct.unpack("!H", data[2:4])[0]
    payload_len, next_header, hop_limit = struct.unpack("!HBB", data[4:8])
    src = str(ipaddress.ip_address(data[8:24]))
    dst = str(ipaddress.ip_address(data[24:40]))
    payload = data[40 : 40 + payload_len]
    # Walk a minimal set of extension headers so transport parsing still works.
    while next_header in {IPPROTO_HOPOPT, IPPROTO_ROUTING}:
        if len(payload) < 8:
            raise DecodeError("short IPv6 extension header")
        next_header = payload[0]
        hdr_ext_len = (payload[1] + 1) * 8
        payload = payload[hdr_ext_len:]
    if next_header == IPPROTO_FRAGMENT:
        if len(payload) < 8:
            raise DecodeError("short IPv6 fragment header")
        next_header = payload[0]
        payload = payload[8:]
    return Ipv6Packet(
        src=src, dst=dst, next_header=next_header, hop_limit=hop_limit,
        payload=payload, traffic_class=traffic, flow_label=flow,
    )


def decode_tcp(data: bytes) -> TcpSegment:
    if len(data) < 20:
        raise DecodeError("short TCP header")
    src_port, dst_port, seq, ack, offset_flags, window = struct.unpack("!HHIIHH", data[:16])
    data_offset = (offset_flags >> 12) * 4
    flags = offset_flags & 0x01FF
    if data_offset < 20 or len(data) < data_offset:
        raise DecodeError("bad TCP data offset")
    urg = struct.unpack("!H", data[18:20])[0]
    return TcpSegment(
        src_port=src_port, dst_port=dst_port, seq=seq, ack=ack, flags=flags,
        window=window, payload=data[data_offset:], data_offset=data_offset, urg=urg,
    )


def decode_udp(data: bytes) -> UdpDatagram:
    if len(data) < 8:
        raise DecodeError("short UDP header")
    src_port, dst_port, length, _checksum = struct.unpack("!HHHH", data[:8])
    return UdpDatagram(src_port=src_port, dst_port=dst_port, length=length,
                       payload=data[8:length] if length >= 8 else b"")


def decode_icmpv4(data: bytes) -> Icmpv4Message:
    if len(data) < 4:
        raise DecodeError("short ICMPv4 header")
    return Icmpv4Message(type=data[0], code=data[1], payload=data[4:])


def decode_icmpv6_neighbor(data: bytes) -> Icmpv6NeighborMessage:
    if len(data) < 4:
        raise DecodeError("short ICMPv6 header")
    msg = Icmpv6NeighborMessage(type=data[0], code=data[1], payload=data[4:])
    if msg.type == 133:  # Router Solicitation
        return msg
    if msg.type == 134:  # Router Advertisement
        if len(data) >= 16:
            flags = data[4]
            msg.router = True
            msg.hop_limit = data[5]
        return msg
    if msg.type in (135, 136):  # Neighbor Solicitation / Advertisement
        if len(data) >= 24:
            flags = data[4] if msg.type == 136 else 0
            msg.router = bool(flags & 0x80)
            msg.solicited = bool(flags & 0x40)
            msg.override = bool(flags & 0x20)
            msg.target = str(ipaddress.ip_address(data[8:24]))
            # Target link-layer address option (type 1=source, 2=target)
            opts = data[24:]
            if len(opts) >= 8 and opts[0] in (1, 2):
                msg.source_link_layer = _mac(opts[2:8]) if opts[0] == 1 else msg.source_link_layer
                msg.target_link_layer = _mac(opts[2:8]) if opts[0] == 2 else msg.target_link_layer
    return msg


def decode_payload(linktype: int, data: bytes) -> Any:
    """Top-level dispatcher used by parsers."""
    if linktype == 1:  # Ethernet
        return decode_ethernet(data)
    if linktype == 101 or linktype == 12:  # raw IP / raw
        if data and data[0] >> 4 == 6:
            return decode_ipv6(data)
        return decode_ipv4(data)
    if linktype == 113:  # Linux cooked capture v1
        if len(data) < 16:
            raise DecodeError("short SLL header")
        proto = struct.unpack("!H", data[14:16])[0]
        payload = data[16:]
        if proto == ETHERTYPE_IPV4:
            return decode_ipv4(payload)
        if proto == ETHERTYPE_IPV6:
            return decode_ipv6(payload)
        if proto == ETHERTYPE_ARP:
            return decode_arp(payload)
        return payload
    # Unknown link type: return raw bytes and let the parser decide.
    return data


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw[:6])
