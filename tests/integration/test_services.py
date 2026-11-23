from __future__ import annotations

import socket

from adversarylab.adversary.actions import FakeActionRunner, ServiceBackedActionRunner
from adversarylab.protocols import dhcp, dns
from adversarylab.services.dhcp_server import DhcpServer, DhcpServerConfig
from adversarylab.services.dns_server import DnsServer, DnsServerConfig
from adversarylab.services.http_server import LabHttpServer


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_dns_server_udp_answer_and_spoof():
    port = _free_port()
    server = DnsServer(DnsServerConfig(bind_addr="127.0.0.1", port=port, serve_tcp=False))
    server.add_record("api.lab.test", dns.a_record("api.lab.test", "10.10.0.50", ttl=30))
    server.start()
    try:
        query = dns.DnsMessage(msg_id=42, flags=dns.FLAG_RD,
                               questions=[dns.DnsQuestion("api.lab.test", dns.TYPE_A)])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            sock.sendto(dns.build_message(query), ("127.0.0.1", port))
            data, _ = sock.recvfrom(4096)
        response = dns.parse_message(data)
        assert response.answers[0].address == "10.10.0.50"
        assert server.query_log[-1].action == "answered"

        def responder(question, _query):
            if question.name.startswith("spoof"):
                return [dns.a_record(question.name, "10.10.0.250", 5)]
            return None

        server.config.responder = responder
        spoof_query = dns.DnsMessage(msg_id=43, flags=dns.FLAG_RD,
                                     questions=[dns.DnsQuestion("spoof.lab.test", dns.TYPE_A)])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            sock.sendto(dns.build_message(spoof_query), ("127.0.0.1", port))
            data, _ = sock.recvfrom(4096)
        assert dns.parse_message(data).answers[0].address == "10.10.0.250"
        assert server.query_log[-1].action == "spoofed"
    finally:
        server.stop()


def test_dns_server_drop():
    port = _free_port()
    server = DnsServer(DnsServerConfig(bind_addr="127.0.0.1", port=port, serve_tcp=False,
                                       drop_names={"secret.lab.test"}))
    server.start()
    try:
        query = dns.DnsMessage(msg_id=1, flags=dns.FLAG_RD,
                               questions=[dns.DnsQuestion("secret.lab.test", dns.TYPE_A)])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.5)
            sock.sendto(dns.build_message(query), ("127.0.0.1", port))
            try:
                sock.recvfrom(4096)
                raise AssertionError("drop policy should not answer")
            except TimeoutError:
                pass
        assert server.query_log[-1].action == "dropped"
    finally:
        server.stop()


def test_dhcp_server_offer_and_ack():
    server = DhcpServer(DhcpServerConfig(server_id="10.10.0.1", router="10.10.0.1",
                                         dns_servers=["10.10.0.1"],
                                         allowed_macs={"02:00:00:00:00:01"}))
    discover = dhcp.DhcpMessage(
        op=dhcp.OP_REQUEST, htype=1, hlen=6, hops=0, xid=5, secs=0, flags=0x8000,
        ciaddr="0.0.0.0", yiaddr="0.0.0.0", siaddr="0.0.0.0", giaddr="0.0.0.0",
        chaddr=bytes.fromhex("020000000001"),
        options={dhcp.OPT_MSGTYPE: bytes([dhcp.MSGTYPE_DISCOVER])},
    )
    offer_raw, _ = server.handle_message(dhcp.build_message(discover))
    offer = dhcp.parse_message(offer_raw)
    assert offer.msg_type == dhcp.MSGTYPE_OFFER
    assert offer.yiaddr == "10.10.0.50"

    request = dhcp.DhcpMessage(
        op=dhcp.OP_REQUEST, htype=1, hlen=6, hops=0, xid=5, secs=0, flags=0,
        ciaddr="0.0.0.0", yiaddr="0.0.0.0", siaddr="0.0.0.0", giaddr="0.0.0.0",
        chaddr=bytes.fromhex("020000000001"),
        options={dhcp.OPT_MSGTYPE: bytes([dhcp.MSGTYPE_REQUEST]),
                 dhcp.OPT_REQUESTED_IP: bytes([10, 10, 0, 50])},
    )
    ack_raw, _ = server.handle_message(dhcp.build_message(request))
    ack = dhcp.parse_message(ack_raw)
    assert ack.msg_type == dhcp.MSGTYPE_ACK


def test_dhcp_ignores_unauthorized_mac():
    server = DhcpServer(DhcpServerConfig(allowed_macs={"02:00:00:00:00:01"}))
    discover = dhcp.DhcpMessage(
        op=dhcp.OP_REQUEST, htype=1, hlen=6, hops=0, xid=9, secs=0, flags=0,
        ciaddr="0.0.0.0", yiaddr="0.0.0.0", siaddr="0.0.0.0", giaddr="0.0.0.0",
        chaddr=bytes.fromhex("020000000099"),
        options={dhcp.OPT_MSGTYPE: bytes([dhcp.MSGTYPE_DISCOVER])},
    )
    response, _ = server.handle_message(dhcp.build_message(discover))
    assert response is None
    assert server.message_log[-1]["action"] == "ignored"


def test_http_server_request_logged():
    port = _free_port()
    server = LabHttpServer(bind_addr="127.0.0.1", port=port)
    server.add_simple_route("plain.lab.test", path="/", body="hello")
    server.start()
    try:
        import urllib.request

        response = urllib.request.urlopen(
            f"http://127.0.0.1:{port}/", timeout=2,
            context=None,
        ) if False else None
        # urllib does not set an arbitrary Host header easily; use http.client.
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/", headers={"Host": "plain.lab.test"})
        response = conn.getresponse()
        assert response.status == 200
        assert response.read() == b"hello"
        assert server.log[-1].host == "plain.lab.test"
        assert server.log[-1].method == "GET"
    finally:
        server.stop()


def test_fake_action_runner_records_and_reverts():
    runner = FakeActionRunner()
    result = runner.perform("dns_spoof", qname="x", answer="10.0.0.1")
    assert result.success
    assert runner.actions[0][0] == "dns_spoof"
    runner.revert_all()
    assert runner.actions == []


def test_service_runner_unknown_action():
    runner = ServiceBackedActionRunner()
    result = runner.perform("does_not_exist")
    assert not result.success
    assert "unknown action" in result.error
