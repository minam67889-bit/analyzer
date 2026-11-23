"""QUIC header metadata (RFC 9000).

Only header fields that are legitimately visible to a passive observer are extracted.
QUIC Initial packet *payloads* are protected with Initial keys derived from the DCID, so
the encapsulated TLS ClientHello (and any SNI) is not recoverable by a passive observer.
This module therefore does not attempt to decrypt anything and explicitly reports the
payload as protected.
"""

from __future__ import annotations

from dataclasses import dataclass


class QuicError(ValueError):
    pass


@dataclass
class QuicHeader:
    header_form: str  # "long" | "short" | "unknown"
    fixed_bit: bool
    version: int | None
    dcid: str
    scid: str
    long_packet_type: str | None
    token_length: int | None
    length: int | None
    payload_protected: bool
    raw_first_byte: int

    def to_dict(self) -> dict:
        return {
            "header_form": self.header_form,
            "fixed_bit": self.fixed_bit,
            "version": f"0x{self.version:08x}" if self.version is not None else None,
            "dcid": self.dcid,
            "scid": self.scid,
            "long_packet_type": self.long_packet_type,
            "token_length": self.token_length,
            "length": self.length,
            "payload_protected": self.payload_protected,
            "sni": None,
            "alpn": [],
        }


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        raise QuicError("truncated varint")
    first = data[pos]
    length = 1 << (first >> 6)
    if pos + length > len(data):
        raise QuicError("truncated varint")
    value = first & 0x3F
    for i in range(1, length):
        value = (value << 8) | data[pos + i]
    return value, pos + length


def _cid(data: bytes, pos: int) -> tuple[str, int]:
    if pos >= len(data):
        raise QuicError("truncated connection id length")
    length = data[pos]
    pos += 1
    if pos + length > len(data):
        raise QuicError("truncated connection id")
    return data[pos : pos + length].hex(), pos + length


def parse_header(payload: bytes) -> QuicHeader:
    if len(payload) < 7:
        raise QuicError("short QUIC packet")
    first = payload[0]
    if not (first & 0x80):
        # Short header: only DCID is visible (length depends on connection).
        dcid_len = min(len(payload) - 1, 20)
        return QuicHeader(
            header_form="short",
            fixed_bit=bool(first & 0x40),
            version=None,
            dcid=payload[1 : 1 + dcid_len].hex(),
            scid="",
            long_packet_type=None,
            token_length=None,
            length=None,
            payload_protected=True,
            raw_first_byte=first,
        )
    version = int.from_bytes(payload[1:5], "big")
    pos = 5
    dcid, pos = _cid(payload, pos)
    scid, pos = _cid(payload, pos)
    packet_type = (first >> 4) & 0x03
    type_names = {0: "initial", 1: "0-RTT", 2: "handshake", 3: "retry"}
    long_type = type_names.get(packet_type)
    token_length: int | None = None
    length: int | None = None
    if version != 0 and long_type in {"initial", "0-RTT", "handshake"}:
        token_length, pos = read_varint(payload, pos)
        if long_type == "initial":
            pos += token_length
        length, pos = read_varint(payload, pos)
    elif version == 0:
        long_type = "version_negotiation"
    return QuicHeader(
        header_form="long",
        fixed_bit=bool(first & 0x40),
        version=version,
        dcid=dcid,
        scid=scid,
        long_packet_type=long_type,
        token_length=token_length,
        length=length,
        payload_protected=True,
        raw_first_byte=first,
    )
