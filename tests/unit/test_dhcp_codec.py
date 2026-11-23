from __future__ import annotations

from adversarylab.protocols import dhcp


def _discover(xid=0xABCDEF):
    return dhcp.DhcpMessage(
        op=dhcp.OP_REQUEST, htype=1, hlen=6, hops=0, xid=xid, secs=0, flags=0x8000,
        ciaddr="0.0.0.0", yiaddr="0.0.0.0", siaddr="0.0.0.0", giaddr="0.0.0.0",
        chaddr=bytes.fromhex("020000000001"),
        options={dhcp.OPT_MSGTYPE: bytes([dhcp.MSGTYPE_DISCOVER]),
                 dhcp.OPT_HOSTNAME: b"test-device"},
    )


def test_discover_roundtrip():
    msg = _discover()
    parsed = dhcp.parse_message(dhcp.build_message(msg))
    assert parsed.msg_type == dhcp.MSGTYPE_DISCOVER
    assert parsed.msg_type_name == "DISCOVER"
    assert parsed.client_mac() == "02:00:00:00:00:01"
    assert parsed.get(dhcp.OPT_HOSTNAME) == b"test-device"


def test_offer_options():
    msg = dhcp.make_offer(
        _discover(), server_id="10.10.0.1", offered_ip="10.10.0.50",
        subnet_mask="255.255.255.0", router="10.10.0.1",
        dns_servers=["10.10.0.1", "10.10.0.2"], lease_time=7200,
    )
    parsed = dhcp.parse_message(dhcp.build_message(msg))
    assert parsed.msg_type == dhcp.MSGTYPE_OFFER
    assert parsed.yiaddr == "10.10.0.50"
    assert parsed.get(dhcp.OPT_ROUTER) == b"\x0a\x0a\x00\x01"
    assert parsed.get(dhcp.OPT_DNS) == b"\x0a\x0a\x00\x01\x0a\x0a\x00\x02"
    assert parsed.get(dhcp.OPT_LEASE_TIME) == b"\x00\x00\x1c\x20"


def test_ack_roundtrip():
    request = dhcp.DhcpMessage(
        op=dhcp.OP_REQUEST, htype=1, hlen=6, hops=0, xid=1, secs=0, flags=0,
        ciaddr="0.0.0.0", yiaddr="0.0.0.0", siaddr="0.0.0.0", giaddr="0.0.0.0",
        chaddr=bytes.fromhex("020000000001"),
        options={dhcp.OPT_MSGTYPE: bytes([dhcp.MSGTYPE_REQUEST]),
                 dhcp.OPT_REQUESTED_IP: b"\x0a\x0a\x00\x32"},
    )
    ack = dhcp.make_ack(request, server_id="10.10.0.1", offered_ip="10.10.0.50",
                        subnet_mask="255.255.255.0", router="10.10.0.1",
                        dns_servers=["10.10.0.1"])
    parsed = dhcp.parse_message(dhcp.build_message(ack))
    assert parsed.msg_type == dhcp.MSGTYPE_ACK
    assert parsed.yiaddr == "10.10.0.50"
