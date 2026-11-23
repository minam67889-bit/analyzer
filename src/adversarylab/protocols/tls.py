"""TLS record / ClientHello metadata extraction.

The laboratory never decrypts application data. This module extracts only what a passive
observer can legitimately see: record type, legacy version, handshake type, SNI, ALPN,
supported versions, cipher suites, extensions, and a JA3-style fingerprint.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Any

CONTENT_HANDSHAKE = 22
HANDSHAKE_CLIENT_HELLO = 1

EXT_SERVER_NAME = 0
EXT_ALPN = 16
EXT_SUPPORTED_VERSIONS = 43
EXT_KEY_SHARE = 51
EXT_EC_POINT_FORMATS = 11
EXT_SUPPORTED_GROUPS = 10


class TlsError(ValueError):
    pass


@dataclass
class ClientHelloMetadata:
    legacy_version: int
    cipher_suites: list[int]
    extensions: list[int]
    sni: str | None = None
    alpn: list[str] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)
    supported_groups: list[int] = field(default_factory=list)
    ec_point_formats: list[int] = field(default_factory=list)
    has_key_share: bool = False
    ja3: str = ""
    ja3_md5: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "legacy_version": f"0x{self.legacy_version:04x}",
            "cipher_suites": [f"0x{c:04x}" for c in self.cipher_suites],
            "extensions": self.extensions,
            "sni": self.sni,
            "alpn": self.alpn,
            "supported_versions": [f"0x{v:04x}" for v in self.supported_versions],
            "supported_groups": self.supported_groups,
            "ec_point_formats": self.ec_point_formats,
            "has_key_share": self.has_key_share,
            "ja3": self.ja3,
            "ja3_md5": self.ja3_md5,
        }


@dataclass
class TlsRecord:
    content_type: int
    version: int
    payload: bytes


def parse_records(data: bytes) -> list[TlsRecord]:
    records: list[TlsRecord] = []
    pos = 0
    while pos + 5 <= len(data):
        content_type = data[pos]
        version = struct.unpack("!H", data[pos + 1 : pos + 3])[0]
        length = struct.unpack("!H", data[pos + 3 : pos + 5])[0]
        pos += 5
        if pos + length > len(data):
            raise TlsError("truncated TLS record")
        records.append(TlsRecord(content_type, version, data[pos : pos + length]))
        pos += length
    return records


def parse_client_hello(data: bytes) -> ClientHelloMetadata:
    """Parse a TLS record payload (or a bare ClientHello body)."""
    records = parse_records(data)
    handshake = None
    for record in records:
        if record.content_type == CONTENT_HANDSHAKE and record.payload:
            handshake = record.payload
            break
    if handshake is None and data and data[0] == HANDSHAKE_CLIENT_HELLO:
        handshake = data
    if handshake is None:
        raise TlsError("no ClientHello found")
    if len(handshake) < 4 or handshake[0] != HANDSHAKE_CLIENT_HELLO:
        raise TlsError("not a ClientHello handshake")
    body = handshake[4:]
    if len(body) < 2:
        raise TlsError("truncated ClientHello")
    legacy_version = struct.unpack("!H", body[:2])[0]
    pos = 2 + 32
    if pos >= len(body):
        raise TlsError("truncated ClientHello random")
    session_len = body[pos]
    pos += 1 + session_len
    if pos + 2 > len(body):
        raise TlsError("truncated cipher suites")
    cs_len = struct.unpack("!H", body[pos : pos + 2])[0]
    pos += 2
    if pos + cs_len > len(body):
        raise TlsError("truncated cipher suite list")
    cipher_suites = [struct.unpack("!H", body[pos + i : pos + i + 2])[0]
                     for i in range(0, cs_len, 2)]
    pos += cs_len
    if pos >= len(body):
        raise TlsError("missing compression methods")
    comp_len = body[pos]
    pos += 1 + comp_len
    extensions: list[int] = []
    alpn: list[str] = []
    supported_versions: list[int] = []
    supported_groups: list[int] = []
    ec_point_formats: list[int] = []
    has_key_share = False
    sni: str | None = None
    if pos + 2 <= len(body):
        ext_total = struct.unpack("!H", body[pos : pos + 2])[0]
        pos += 2
        end = min(len(body), pos + ext_total)
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", body[pos : pos + 4])
            ext_data = body[pos + 4 : pos + 4 + ext_len]
            extensions.append(ext_type)
            if ext_type == EXT_SERVER_NAME and len(ext_data) >= 5:
                # server_name_list: type(1) + length(2) + name
                name_type = ext_data[0]
                name_len = struct.unpack("!H", ext_data[1:3])[0]
                if name_type == 0:
                    sni = ext_data[3 : 3 + name_len].decode("ascii", "replace")
            elif ext_type == EXT_ALPN:
                alpn = _parse_alpn(ext_data)
            elif ext_type == EXT_SUPPORTED_VERSIONS:
                supported_versions = _parse_u16_list(ext_data)
            elif ext_type == EXT_SUPPORTED_GROUPS:
                supported_groups = _parse_u16_list(ext_data)
            elif ext_type == EXT_EC_POINT_FORMATS and ext_data:
                ec_point_formats = list(ext_data[1:])
            elif ext_type == EXT_KEY_SHARE:
                has_key_share = True
            pos += 4 + ext_len
    ja3, ja3_md5 = compute_ja3(legacy_version, cipher_suites, extensions,
                               supported_groups, ec_point_formats)
    return ClientHelloMetadata(
        legacy_version=legacy_version,
        cipher_suites=cipher_suites,
        extensions=extensions,
        sni=sni,
        alpn=alpn,
        supported_versions=supported_versions,
        supported_groups=supported_groups,
        ec_point_formats=ec_point_formats,
        has_key_share=has_key_share,
        ja3=ja3,
        ja3_md5=ja3_md5,
    )


def _parse_alpn(data: bytes) -> list[str]:
    if len(data) < 2:
        return []
    total = struct.unpack("!H", data[:2])[0]
    pos = 2
    out: list[str] = []
    end = min(len(data), 2 + total)
    while pos < end:
        length = data[pos]
        out.append(data[pos + 1 : pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length
    return out


def _parse_u16_list(data: bytes) -> list[int]:
    if len(data) < 1:
        return []
    length = data[0]
    return [struct.unpack("!H", data[1 + i : 3 + i])[0]
            for i in range(0, min(length, len(data) - 1), 2)]


def compute_ja3(
    legacy_version: int,
    cipher_suites: list[int],
    extensions: list[int],
    supported_groups: list[int],
    ec_point_formats: list[int],
) -> tuple[str, str]:
    """Standard JA3 string and its MD5 (/sslfox/JA3 convention)."""
    exts = ",".join(str(e) for e in extensions)
    curves = ",".join(str(g) for g in supported_groups)
    formats = ",".join(str(f) for f in ec_point_formats)
    ja3 = ",".join([
        str(legacy_version),
        ",".join(str(c) for c in cipher_suites) or "-",
        exts or "-",
        curves or "-",
        formats or "-",
    ])
    return ja3, hashlib.md5(ja3.encode("ascii")).hexdigest()
