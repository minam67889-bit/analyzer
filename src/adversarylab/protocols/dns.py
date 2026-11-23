"""DNS wire codec (RFC 1035, RFC 3596, RFC 6891).

Pure-Python, no dependencies. Supports name compression, EDNS0 OPT records and the
record types needed by the laboratory (A, AAAA, CNAME, NS, PTR, TXT, SRV, HTTPS).
"""

from __future__ import annotations

import dataclasses
import struct
from collections.abc import Iterable
from dataclasses import dataclass, field

# Record types
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33
TYPE_OPT = 41
TYPE_HTTPS = 65

CLASS_IN = 1

# Flags
FLAG_QR = 0x8000
FLAG_AA = 0x0400
FLAG_TC = 0x0200
FLAG_RD = 0x0100
FLAG_RA = 0x0080
FLAG_Z = 0x0040
FLAG_AD = 0x0020
FLAG_CD = 0x0010

RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4
RCODE_REFUSED = 5


class DnsError(ValueError):
    pass


@dataclass
class DnsQuestion:
    name: str
    qtype: int
    qclass: int = CLASS_IN


@dataclass
class DnsRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes = b""
    # Decoded convenience fields for common types
    address: str | None = None
    cname: str | None = None
    text: str | None = None
    https_priority: int | None = None
    https_target: str | None = None


@dataclass
class DnsMessage:
    msg_id: int
    flags: int
    questions: list[DnsQuestion] = field(default_factory=list)
    answers: list[DnsRecord] = field(default_factory=list)
    authority: list[DnsRecord] = field(default_factory=list)
    additional: list[DnsRecord] = field(default_factory=list)

    @property
    def is_response(self) -> bool:
        return bool(self.flags & FLAG_QR)

    @property
    def rcode(self) -> int:
        return self.flags & 0x000F

    @property
    def opcode(self) -> int:
        return (self.flags >> 11) & 0x000F

    def with_flags(self, **changes: int) -> DnsMessage:
        new_flags = self.flags
        for key, value in changes.items():
            bit = {
                "qr": FLAG_QR,
                "aa": FLAG_AA,
                "tc": FLAG_TC,
                "rd": FLAG_RD,
                "ra": FLAG_RA,
                "ad": FLAG_AD,
                "cd": FLAG_CD,
            }.get(key)
            if bit is None:
                raise DnsError(f"unknown flag {key}")
            new_flags = (new_flags & ~bit) | (value & bit)
        return dataclasses.replace(self, flags=new_flags)


# ----------------------------------------------------------------------
# Name handling
# ----------------------------------------------------------------------
def encode_name(name: str) -> bytes:
    out = bytearray()
    name = name.rstrip(".")
    if name:
        for label in name.split("."):
            raw = label.encode("idna") if _needs_idna(label) else label.encode("ascii")
            if len(raw) > 63:
                raise DnsError(f"DNS label too long: {label!r}")
            out.append(len(raw))
            out.extend(raw)
    out.append(0)
    return bytes(out)


def _needs_idna(label: str) -> bool:
    try:
        label.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True


def _read_name(data: bytes, offset: int, *, _depth: int = 0) -> tuple[str, int]:
    if _depth > 128:
        raise DnsError("DNS name compression loop")
    labels: list[str] = []
    pos = offset
    jumped = False
    end_offset = offset
    while True:
        if pos >= len(data):
            raise DnsError("truncated DNS name")
        length = data[pos]
        if length == 0:
            pos += 1
            if not jumped:
                end_offset = pos
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise DnsError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                end_offset = pos + 2
            jumped = True
            pos = pointer
            _depth += 1
            if _depth > 128:
                raise DnsError("DNS name compression loop")
            continue
        if length & 0xC0:
            raise DnsError(f"invalid DNS label type {length:#x}")
        pos += 1
        if pos + length > len(data):
            raise DnsError("truncated DNS label")
        labels.append(data[pos : pos + length].decode("ascii", "replace"))
        pos += length
    name = ".".join(labels)
    return (name + ".") if name else ".", end_offset


# ----------------------------------------------------------------------
# Parsing
# ----------------------------------------------------------------------
def parse_message(data: bytes) -> DnsMessage:
    if len(data) < 12:
        raise DnsError("DNS message shorter than header")
    msg_id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    questions: list[DnsQuestion] = []
    for _ in range(qd):
        name, offset = _read_name(data, offset)
        if offset + 4 > len(data):
            raise DnsError("truncated question")
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        questions.append(DnsQuestion(name=name, qtype=qtype, qclass=qclass))
    answers = _parse_rrs(data, offset, an)
    offset = _skip_rrs(data, offset, an)
    authority = _parse_rrs(data, offset, ns)
    offset = _skip_rrs(data, offset, ns)
    additional = _parse_rrs(data, offset, ar)
    return DnsMessage(msg_id=msg_id, flags=flags, questions=questions,
                      answers=answers, authority=authority, additional=additional)


def _parse_rrs(data: bytes, offset: int, count: int) -> list[DnsRecord]:
    records: list[DnsRecord] = []
    for _ in range(count):
        if offset >= len(data):
            raise DnsError("truncated resource record")
        name, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            raise DnsError("truncated resource record header")
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            raise DnsError("truncated rdata")
        rdata = data[offset : offset + rdlength]
        offset += rdlength
        records.append(_decode_rr(name, rtype, rclass, ttl, rdata))
    return records


def _skip_rrs(data: bytes, offset: int, count: int) -> int:
    for _ in range(count):
        _, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            raise DnsError("truncated resource record header")
        rdlength = struct.unpack("!H", data[offset + 8 : offset + 10])[0]
        offset += 10 + rdlength
    return offset


def _decode_rr(name: str, rtype: int, rclass: int, ttl: int, rdata: bytes) -> DnsRecord:
    record = DnsRecord(name=name, rtype=rtype, rclass=rclass, ttl=ttl, rdata=rdata)
    try:
        if rtype == TYPE_A and len(rdata) == 4:
            record.address = ".".join(str(b) for b in rdata)
        elif rtype == TYPE_AAAA and len(rdata) == 16:
            import ipaddress

            record.address = str(ipaddress.IPv6Address(rdata))
        elif rtype in {TYPE_CNAME, TYPE_NS, TYPE_PTR}:
            record.cname, _ = _read_name(rdata, 0)
        elif rtype == TYPE_TXT:
            texts = []
            pos = 0
            while pos < len(rdata):
                length = rdata[pos]
                texts.append(rdata[pos + 1 : pos + 1 + length].decode("utf-8", "replace"))
                pos += 1 + length
            record.text = "".join(texts)
        elif rtype == TYPE_HTTPS:
            if len(rdata) >= 2:
                record.https_priority = struct.unpack("!H", rdata[:2])[0]
                record.https_target, _ = _read_name(rdata, 2)
    except DnsError:
        pass
    return record


# ----------------------------------------------------------------------
# Building
# ----------------------------------------------------------------------
def build_message(msg: DnsMessage) -> bytes:
    out = bytearray()
    out.extend(struct.pack("!HHHHHH", msg.msg_id, msg.flags,
                           len(msg.questions), len(msg.answers),
                           len(msg.authority), len(msg.additional)))
    for q in msg.questions:
        out.extend(encode_name(q.name))
        out.extend(struct.pack("!HH", q.qtype, q.qclass))
    for section in (msg.answers, msg.authority, msg.additional):
        for rr in section:
            out.extend(_encode_rr(rr))
    return bytes(out)


def _encode_rr(record: DnsRecord) -> bytes:
    out = bytearray()
    out.extend(encode_name(record.name))
    out.extend(struct.pack("!HHI", record.rtype, record.rclass, record.ttl))
    rdata = record.rdata
    if record.address and record.rtype == TYPE_A:
        rdata = bytes(int(x) for x in record.address.split("."))
    elif record.address and record.rtype == TYPE_AAAA:
        import ipaddress

        rdata = ipaddress.IPv6Address(record.address).packed
    elif record.cname and record.rtype in {TYPE_CNAME, TYPE_NS, TYPE_PTR}:
        rdata = encode_name(record.cname)
    elif record.text is not None and record.rtype == TYPE_TXT:
        raw = record.text.encode("utf-8")
        rdata = bytes([len(raw)]) + raw if len(raw) <= 255 else raw
    out.extend(struct.pack("!H", len(rdata)))
    out.extend(rdata)
    return bytes(out)


# ----------------------------------------------------------------------
# Convenience
# ----------------------------------------------------------------------
def make_response(
    query: DnsMessage,
    answers: Iterable[DnsRecord],
    *,
    rcode: int = RCODE_NOERROR,
    aa: bool = True,
    ra: bool = True,
) -> DnsMessage:
    flags = FLAG_QR | FLAG_RD | FLAG_RA if ra else FLAG_QR | FLAG_RD
    if aa:
        flags |= FLAG_AA
    flags = (flags & ~0x000F) | (rcode & 0x000F)
    return DnsMessage(
        msg_id=query.msg_id,
        flags=flags,
        questions=list(query.questions),
        answers=list(answers),
    )


def a_record(name: str, address: str, ttl: int = 60) -> DnsRecord:
    return DnsRecord(name=name, rtype=TYPE_A, rclass=CLASS_IN, ttl=ttl, address=address)


def aaaa_record(name: str, address: str, ttl: int = 60) -> DnsRecord:
    return DnsRecord(name=name, rtype=TYPE_AAAA, rclass=CLASS_IN, ttl=ttl, address=address)


def cname_record(name: str, target: str, ttl: int = 60) -> DnsRecord:
    return DnsRecord(name=name, rtype=TYPE_CNAME, rclass=CLASS_IN, ttl=ttl, cname=target)


def nxdomain(query: DnsMessage) -> DnsMessage:
    return make_response(query, [], rcode=RCODE_NXDOMAIN, aa=True)


def parse_question(data: bytes) -> DnsQuestion:
    msg = parse_message(data)
    if not msg.questions:
        raise DnsError("no question in DNS message")
    return msg.questions[0]
