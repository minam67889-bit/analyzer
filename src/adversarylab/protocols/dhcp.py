"""DHCPv4 wire codec (RFC 2131, RFC 2132).

Supports the message types and options needed by the laboratory: MSGTYPE, SERVER_ID,
REQUESTED_IP, PARAM_REQUEST_LIST, HOSTNAME, CLIENT_ID, MASK, ROUTER, DNS, LEASE_TIME,
RENEWAL, REBINDING, VENDOR_CLASS, END.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import Any

MAGIC_COOKIE = 0x63825363

OP_REQUEST = 1
OP_REPLY = 2

OPT_PAD = 0
OPT_END = 255
OPT_SUBNET_MASK = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_HOSTNAME = 12
OPT_REQUESTED_IP = 50
OPT_LEASE_TIME = 51
OPT_MSGTYPE = 53
OPT_SERVER_ID = 54
OPT_PARAM_REQUEST_LIST = 55
OPT_VENDOR_CLASS = 60
OPT_CLIENT_ID = 61
OPT_RENEWAL = 58
OPT_REBINDING = 59

MSGTYPE_DISCOVER = 1
MSGTYPE_OFFER = 2
MSGTYPE_REQUEST = 3
MSGTYPE_DECLINE = 4
MSGTYPE_ACK = 5
MSGTYPE_NAK = 6
MSGTYPE_RELEASE = 7
MSGTYPE_INFORM = 8

MSG_NAMES = {
    MSGTYPE_DISCOVER: "DISCOVER",
    MSGTYPE_OFFER: "OFFER",
    MSGTYPE_REQUEST: "REQUEST",
    MSGTYPE_DECLINE: "DECLINE",
    MSGTYPE_ACK: "ACK",
    MSGTYPE_NAK: "NAK",
    MSGTYPE_RELEASE: "RELEASE",
    MSGTYPE_INFORM: "INFORM",
}


class DhcpError(ValueError):
    pass


@dataclass
class DhcpMessage:
    op: int
    htype: int
    hlen: int
    hops: int
    xid: int
    secs: int
    flags: int
    ciaddr: str
    yiaddr: str
    siaddr: str
    giaddr: str
    chaddr: bytes
    sname: str = ""
    file: str = ""
    options: dict[int, bytes] = field(default_factory=dict)
    raw_options: bytes = b""

    @property
    def msg_type(self) -> int | None:
        value = self.options.get(OPT_MSGTYPE)
        return value[0] if value else None

    @property
    def msg_type_name(self) -> str:
        mt = self.msg_type
        return MSG_NAMES.get(mt, f"TYPE{mt}") if mt is not None else "UNKNOWN"

    def get(self, code: int, default: Any = None) -> Any:
        return self.options.get(code, default)

    def client_mac(self) -> str:
        return ":".join(f"{b:02x}" for b in self.chaddr[:6])


def _ip(value: str) -> bytes:
    return ipaddress.ip_address(value).packed


def parse_message(data: bytes) -> DhcpMessage:
    if len(data) < 240:
        raise DhcpError("DHCP message shorter than fixed fields")
    op, htype, hlen, hops, xid, secs, flags = struct.unpack("!BBBBIHH", data[:12])
    ciaddr = str(ipaddress.ip_address(data[12:16]))
    yiaddr = str(ipaddress.ip_address(data[16:20]))
    siaddr = str(ipaddress.ip_address(data[20:24]))
    giaddr = str(ipaddress.ip_address(data[24:28]))
    chaddr = data[28 : 28 + hlen]
    sname = data[44:108].split(b"\x00", 1)[0].decode("ascii", "replace")
    file = data[108:236].split(b"\x00", 1)[0].decode("ascii", "replace")
    cookie = struct.unpack("!I", data[236:240])[0]
    if cookie != MAGIC_COOKIE:
        raise DhcpError(f"bad DHCP magic cookie {cookie:#x}")
    options, raw = _parse_options(data[240:])
    return DhcpMessage(
        op=op, htype=htype, hlen=hlen, hops=hops, xid=xid, secs=secs, flags=flags,
        ciaddr=ciaddr, yiaddr=yiaddr, siaddr=siaddr, giaddr=giaddr, chaddr=chaddr,
        sname=sname, file=file, options=options, raw_options=raw,
    )


def _parse_options(data: bytes) -> tuple[dict[int, bytes], bytes]:
    options: dict[int, bytes] = {}
    pos = 0
    while pos < len(data):
        code = data[pos]
        if code == OPT_END:
            break
        if code == OPT_PAD:
            pos += 1
            continue
        if pos + 2 > len(data):
            break
        length = data[pos + 1]
        if pos + 2 + length > len(data):
            break
        options[code] = data[pos + 2 : pos + 2 + length]
        pos += 2 + length
    return options, data


def build_message(msg: DhcpMessage) -> bytes:
    out = bytearray()
    out.extend(struct.pack("!BBBBIHH", msg.op, msg.htype, msg.hlen, msg.hops,
                           msg.xid, msg.secs, msg.flags))
    out.extend(_ip(msg.ciaddr))
    out.extend(_ip(msg.yiaddr))
    out.extend(_ip(msg.siaddr))
    out.extend(_ip(msg.giaddr))
    chaddr = msg.chaddr[: msg.hlen].ljust(16, b"\x00")
    out.extend(chaddr)
    out.extend(msg.sname.encode("ascii", "replace")[:64].ljust(64, b"\x00"))
    out.extend(msg.file.encode("ascii", "replace")[:128].ljust(128, b"\x00"))
    out.extend(struct.pack("!I", MAGIC_COOKIE))
    if msg.raw_options:
        out.extend(msg.raw_options)
    else:
        for code, value in msg.options.items():
            out.append(code)
            out.append(len(value))
            out.extend(value)
    out.append(OPT_END)
    return bytes(out)


def _option(code: int, payload: bytes) -> tuple[int, bytes]:
    return code, payload


def make_offer(
    request: DhcpMessage,
    *,
    server_id: str,
    offered_ip: str,
    subnet_mask: str,
    router: str,
    dns_servers: list[str],
    lease_time: int = 3600,
    hostname: str | None = None,
) -> DhcpMessage:
    options: dict[int, bytes] = {
        OPT_MSGTYPE: bytes([MSGTYPE_OFFER]),
        OPT_SERVER_ID: _ip(server_id),
        OPT_SUBNET_MASK: _ip(subnet_mask),
        OPT_ROUTER: _ip(router),
        OPT_DNS: b"".join(_ip(d) for d in dns_servers),
        OPT_LEASE_TIME: struct.pack("!I", lease_time),
        OPT_RENEWAL: struct.pack("!I", lease_time // 2),
        OPT_REBINDING: struct.pack("!I", int(lease_time * 0.875)),
    }
    if hostname:
        options[OPT_HOSTNAME] = hostname.encode("utf-8")
    return DhcpMessage(
        op=OP_REPLY, htype=1, hlen=6, hops=0, xid=request.xid, secs=0,
        flags=request.flags, ciaddr="0.0.0.0", yiaddr=offered_ip, siaddr=server_id,
        giaddr=request.giaddr, chaddr=request.chaddr, options=options,
    )


def make_ack(
    request: DhcpMessage,
    *,
    server_id: str,
    offered_ip: str,
    subnet_mask: str,
    router: str,
    dns_servers: list[str],
    lease_time: int = 3600,
) -> DhcpMessage:
    options: dict[int, bytes] = {
        OPT_MSGTYPE: bytes([MSGTYPE_ACK]),
        OPT_SERVER_ID: _ip(server_id),
        OPT_SUBNET_MASK: _ip(subnet_mask),
        OPT_ROUTER: _ip(router),
        OPT_DNS: b"".join(_ip(d) for d in dns_servers),
        OPT_LEASE_TIME: struct.pack("!I", lease_time),
        OPT_RENEWAL: struct.pack("!I", lease_time // 2),
        OPT_REBINDING: struct.pack("!I", int(lease_time * 0.875)),
    }
    return DhcpMessage(
        op=OP_REPLY, htype=1, hlen=6, hops=0, xid=request.xid, secs=0,
        flags=request.flags, ciaddr=request.ciaddr, yiaddr=offered_ip, siaddr=server_id,
        giaddr=request.giaddr, chaddr=request.chaddr, options=options,
    )


def make_nak(request: DhcpMessage, *, server_id: str) -> DhcpMessage:
    return DhcpMessage(
        op=OP_REPLY, htype=1, hlen=6, hops=0, xid=request.xid, secs=0,
        flags=request.flags, ciaddr="0.0.0.0", yiaddr="0.0.0.0", siaddr=server_id,
        giaddr=request.giaddr, chaddr=request.chaddr,
        options={OPT_MSGTYPE: bytes([MSGTYPE_NAK]), OPT_SERVER_ID: _ip(server_id)},
    )
