"""DHCP event parser."""

from __future__ import annotations

from ...core.events import EventCategory, EventSeverity, EventSource, make_event
from ...protocols import dhcp
from .base import DecodedPacket


class DhcpParser:
    def parse(self, packet: DecodedPacket) -> list:
        if not packet.is_udp:
            return []
        if packet.src_port not in (67, 68) and packet.dst_port not in (67, 68):
            return []
        if not packet.payload:
            return []
        try:
            msg = dhcp.parse_message(packet.payload)
        except dhcp.DhcpError:
            return []
        details = {
            "msg_type": msg.msg_type,
            "msg_type_name": msg.msg_type_name,
            "xid": msg.xid,
            "ciaddr": msg.ciaddr,
            "yiaddr": msg.yiaddr,
            "siaddr": msg.siaddr,
            "giaddr": msg.giaddr,
            "chaddr": msg.client_mac(),
            "flags": msg.flags,
        }
        for code, name in (
            (dhcp.OPT_SUBNET_MASK, "subnet_mask"),
            (dhcp.OPT_ROUTER, "router"),
            (dhcp.OPT_DNS, "dns_servers"),
            (dhcp.OPT_HOSTNAME, "hostname"),
            (dhcp.OPT_LEASE_TIME, "lease_time"),
            (dhcp.OPT_SERVER_ID, "server_id"),
        ):
            value = msg.get(code)
            if value:
                details[name] = _decode_option(code, value)
        return [
            make_event(
                session_id="",
                category=EventCategory.DHCP,
                source=EventSource.PACKET_CAPTURE,
                severity=EventSeverity.INFO,
                summary=f"DHCP {msg.msg_type_name} chaddr={msg.client_mac()} yiaddr={msg.yiaddr}",
                protocol="dhcp",
                src_addr=packet.src,
                dst_addr=packet.dst,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                details=details,
            )
        ]


def _decode_option(code: int, value: bytes):
    import ipaddress

    if code in (dhcp.OPT_SUBNET_MASK, dhcp.OPT_ROUTER, dhcp.OPT_DNS, dhcp.OPT_SERVER_ID):
        if len(value) == 4:
            return str(ipaddress.ip_address(value))
        if len(value) % 4 == 0:
            return [str(ipaddress.ip_address(value[i : i + 4])) for i in range(0, len(value), 4)]
    if code == dhcp.OPT_HOSTNAME:
        return value.decode("utf-8", "replace")
    if code == dhcp.OPT_LEASE_TIME and len(value) == 4:
        import struct

        return struct.unpack("!I", value)[0]
    return value.hex()
