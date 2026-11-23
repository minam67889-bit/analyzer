from __future__ import annotations

import struct

from adversarylab.protocols import tls


def _build_client_hello(sni="lab.test", alpn=None, version=0x0303):
    if alpn is None:
        alpn = ["h2", "http/1.1"]
    body = bytearray()
    body += struct.pack("!H", version)
    body += b"\x11" * 32
    body += b"\x00"  # session id
    ciphers = [0x1301, 0x1302, 0xC02F]
    body += struct.pack("!H", len(ciphers) * 2)
    body += b"".join(struct.pack("!H", c) for c in ciphers)
    body += b"\x01\x00"  # null compression
    exts = bytearray()
    name = sni.encode()
    sni_ext = b"\x00" + struct.pack("!H", len(name)) + name
    exts += struct.pack("!HH", 0, len(sni_ext)) + sni_ext
    alpn_body = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
    alpn_list = struct.pack("!H", len(alpn_body)) + alpn_body
    exts += struct.pack("!HH", 16, len(alpn_list)) + alpn_list
    body += struct.pack("!H", len(exts)) + exts
    handshake = b"\x01" + len(body).to_bytes(3, "big") + bytes(body)
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record


def test_parse_client_hello_sni_alpn():
    hello = tls.parse_client_hello(_build_client_hello())
    assert hello.sni == "lab.test"
    assert hello.alpn == ["h2", "http/1.1"]
    assert hello.cipher_suites == [0x1301, 0x1302, 0xC02F]
    assert hello.legacy_version == 0x0303
    assert hello.ja3_md5


def test_ja3_stable():
    hello = tls.parse_client_hello(_build_client_hello(sni="other.lab"))
    assert hello.ja3.startswith("771,")
    # SNI is not part of JA3.
    assert hello.ja3 == tls.parse_client_hello(_build_client_hello(sni="third.lab")).ja3


def test_truncated_rejected():
    import pytest

    with pytest.raises(tls.TlsError):
        tls.parse_client_hello(b"\x16\x03\x01\x00\x05\x01")
