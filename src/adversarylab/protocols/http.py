"""Minimal HTTP/1.x request/response metadata extraction (no body inspection)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class HttpError(ValueError):
    pass


@dataclass
class HttpRequest:
    method: str
    target: str
    version: str
    headers: dict[str, str] = field(default_factory=dict)
    body_length: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "target": self.target,
            "version": self.version,
            "headers": dict(self.headers),
            "body_length": self.body_length,
        }


@dataclass
class HttpResponse:
    version: str
    status: int
    reason: str
    headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "status": self.status,
            "reason": self.reason,
            "headers": dict(self.headers),
        }


def _split_headers(block: bytes) -> tuple[str, dict[str, str], int]:
    try:
        text = block.decode("latin-1")
    except Exception as exc:  # pragma: no cover
        raise HttpError(str(exc)) from exc
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    if not lines:
        raise HttpError("empty HTTP head")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return lines[0], headers, len(body.encode("latin-1"))


def parse_request(data: bytes) -> HttpRequest:
    if b"\r\n" not in data:
        raise HttpError("incomplete HTTP request line")
    line, headers, body_length = _split_headers(data)
    parts = line.split(" ")
    if len(parts) < 3:
        raise HttpError(f"malformed HTTP request line: {line!r}")
    method, target, version = parts[0], parts[1], parts[2]
    if not version.startswith("HTTP/"):
        raise HttpError(f"not an HTTP request: {line!r}")
    declared = headers.get("content-length")
    if declared and declared.isdigit():
        body_length = int(declared)
    return HttpRequest(method=method, target=target, version=version,
                       headers=headers, body_length=body_length)


def parse_response(data: bytes) -> HttpResponse:
    line, headers, _ = _split_headers(data)
    parts = line.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise HttpError(f"malformed HTTP status line: {line!r}")
    try:
        status = int(parts[1])
    except ValueError as exc:
        raise HttpError(f"bad HTTP status: {parts[1]!r}") from exc
    reason = parts[2] if len(parts) > 2 else ""
    return HttpResponse(version=parts[0], status=status, reason=reason, headers=headers)


def host_from_request(request: HttpRequest) -> str | None:
    host = request.headers.get("host")
    if not host:
        return None
    return host.split(":")[0]


def parse_cookie_header(value: str) -> list[tuple[str, str]]:
    """Parse a request ``Cookie`` header into ``(name, value)`` pairs.

    Only the name/value pairs are extracted; attributes never appear on request headers.
    Malformed pairs are skipped rather than raising, because a capture must not abort an
    assessment.
    """
    pairs: list[tuple[str, str]] = []
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        name, _, cookie_value = chunk.partition("=")
        name = name.strip()
        if name:
            pairs.append((name, cookie_value.strip()))
    return pairs


def parse_set_cookie_header(value: str) -> tuple[str, str, dict[str, Any]]:
    """Parse a response ``Set-Cookie`` header into name, value and attributes."""
    parts = [p.strip() for p in value.split(";") if p.strip()]
    if not parts or "=" not in parts[0]:
        raise HttpError(f"malformed Set-Cookie header: {value!r}")
    name, _, cookie_value = parts[0].partition("=")
    attributes: dict[str, Any] = {}
    for part in parts[1:]:
        key, sep, raw = part.partition("=")
        key = key.strip().lower()
        if not key:
            continue
        if not sep:
            attributes[key] = True
        else:
            attributes[key] = raw.strip().strip('"')
    return name.strip(), cookie_value.strip(), attributes
