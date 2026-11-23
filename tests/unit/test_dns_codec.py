from __future__ import annotations

import pytest

from adversarylab.protocols import dns


def _query(name="example.lab.test", qtype=dns.TYPE_A):
    return dns.DnsMessage(
        msg_id=0x1234,
        flags=dns.FLAG_RD,
        questions=[dns.DnsQuestion(name=name, qtype=qtype)],
    )


def test_query_roundtrip():
    msg = _query()
    parsed = dns.parse_message(dns.build_message(msg))
    assert parsed.msg_id == msg.msg_id
    assert parsed.questions[0].name == "example.lab.test."
    assert parsed.questions[0].qtype == dns.TYPE_A


def test_response_with_compression():
    query = _query()
    answer = dns.a_record("example.lab.test", "10.10.0.50", ttl=30)
    response = dns.make_response(query, [answer])
    raw = dns.build_message(response)
    parsed = dns.parse_message(raw)
    assert parsed.is_response
    assert parsed.answers[0].address == "10.10.0.50"
    assert parsed.answers[0].ttl == 30


def test_aaaa_and_cname_decode():
    query = _query(qtype=dns.TYPE_AAAA)
    response = dns.make_response(query, [dns.aaaa_record("example.lab.test", "fd00::1")])
    parsed = dns.parse_message(dns.build_message(response))
    assert parsed.answers[0].address == "fd00::1"

    cname = dns.make_response(query, [dns.cname_record("www.lab.test", "lab.test")])
    parsed = dns.parse_message(dns.build_message(cname))
    assert parsed.answers[0].cname == "lab.test."


def test_txt_record():
    query = _query(qtype=dns.TYPE_TXT)
    response = dns.make_response(query, [dns.DnsRecord(
        name="example.lab.test.", rtype=dns.TYPE_TXT, rclass=dns.CLASS_IN, ttl=5,
        text="hello")])
    parsed = dns.parse_message(dns.build_message(response))
    assert parsed.answers[0].text == "hello"


def test_nxdomain():
    query = _query()
    response = dns.nxdomain(query)
    parsed = dns.parse_message(dns.build_message(response))
    assert parsed.rcode == dns.RCODE_NXDOMAIN


def test_compression_loop_rejected():
    # A name that points to itself.
    raw = bytearray(b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    raw.extend(b"\xc0\x0c\x00\x01\x00\x01")
    with pytest.raises(dns.DnsError):
        dns.parse_message(bytes(raw))


def test_short_message_rejected():
    with pytest.raises(dns.DnsError):
        dns.parse_message(b"\x00\x01")
