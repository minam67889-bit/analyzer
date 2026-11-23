"""Laboratory HTTP/WebSocket server with Host-based routing and captive portal support.

Serves only laboratory endpoints. Every request is logged with method, target, Host and a
small header subset. WebSocket support is a minimal RFC 6455 handshake + text frames for
lab protocol testing. No third-party dependencies.
"""

from __future__ import annotations

import base64
import hashlib
import socket
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from ..clock import Clock, SystemClock
from ..core.events import EventCategory, EventSeverity, EventSource, make_event
from ..logging_config import get_logger

logger = get_logger(__name__)

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


@dataclass
class CookieRouteConfig:
    """One synthetic cookie a laboratory endpoint should issue."""

    name: str
    value: str
    secure: bool = False
    httponly: bool = False
    samesite: str = ""
    max_age: int | None = None
    path: str = "/"
    purpose: str = "synthetic test cookie"

    def header(self) -> str:
        parts = [f"{self.name}={self.value}", f"Path={self.path}"]
        if self.secure:
            parts.append("Secure")
        if self.httponly:
            parts.append("HttpOnly")
        if self.samesite:
            parts.append(f"SameSite={self.samesite}")
        if self.max_age is not None:
            parts.append(f"Max-Age={self.max_age}")
        return "; ".join(parts)


@dataclass
class HttpRoute:
    host: str
    path: str
    status: int = 200
    body: bytes = b""
    content_type: str = "text/html; charset=utf-8"
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[CookieRouteConfig] = field(default_factory=list)


@dataclass
class HttpLogEntry:
    timestamp: str
    client: str
    method: str
    target: str
    host: str | None
    status: int | None
    headers: dict[str, str]
    route: str | None = None
    set_cookies: list[str] = field(default_factory=list)
    evidence_ref: str | None = None


class LabHttpServer:
    def __init__(
        self,
        *,
        bind_addr: str = "0.0.0.0",
        port: int = 80,
        tls_port: int | None = None,
        routes: list[HttpRoute] | None = None,
        bus: Callable[..., None] | None = None,
        clock: Clock | None = None,
        session_id: str = "",
        device_id: str | None = None,
        default_body: bytes | None = None,
        evidence: Any | None = None,
        test_id: str | None = None,
        scenario_id: str | None = None,
    ) -> None:
        self.bind_addr = bind_addr
        self.port = port
        self.tls_port = tls_port
        self.routes = routes or []
        self.bus = bus
        self.clock = clock or SystemClock()
        self.session_id = session_id
        self.device_id = device_id
        self.default_body = default_body or b"<html><body><h1>Adversary Lab</h1></body></html>"
        # Optional laboratory evidence store: each exchange is written to the hashed
        # evidence bundle so a finding can point at the exact request that carried it.
        self.evidence = evidence
        self.test_id = test_id
        self.scenario_id = scenario_id
        self.log: list[HttpLogEntry] = []
        self._httpd: ThreadingHTTPServer | None = None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    def add_route(self, route: HttpRoute) -> None:
        self.routes.append(route)

    def add_simple_route(self, host: str, path: str = "/", body: str | bytes = "",
                         status: int = 200, content_type: str = "text/html; charset=utf-8") -> None:
        data = body.encode() if isinstance(body, str) else body
        self.routes.append(HttpRoute(host=host, path=path, status=status, body=data,
                                     content_type=content_type))

    def add_cookie_route(
        self,
        host: str,
        path: str,
        cookies: list[CookieRouteConfig],
        *,
        body: str | bytes = "",
        status: int = 200,
        content_type: str = "text/html; charset=utf-8",
    ) -> HttpRoute:
        data = body.encode() if isinstance(body, str) else body
        route = HttpRoute(host=host, path=path, status=status, body=data,
                          content_type=content_type, cookies=list(cookies))
        self.routes.append(route)
        return route

    def find_route(self, host: str | None, path: str) -> HttpRoute | None:
        host = (host or "").lower()
        best: HttpRoute | None = None
        best_len = -1
        for route in self.routes:
            route_host = route.host.lower()
            if host != route_host and not host.endswith("." + route_host):
                continue
            if path.startswith(route.path) and len(route.path) > best_len:
                best = route
                best_len = len(route.path)
        return best

    # ------------------------------------------------------------------
    def start(self) -> None:
        with self._lock:
            if self._httpd:
                return
            server = self

            class Handler(BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"

                def log_message(self, fmt: str, *args: object) -> None:  # silence stderr
                    pass

                def do_GET(self) -> None:
                    server._handle(self, "GET")

                def do_POST(self) -> None:
                    server._handle(self, "POST")

                def do_HEAD(self) -> None:
                    server._handle(self, "HEAD")

                def do_OPTIONS(self) -> None:
                    server._handle(self, "OPTIONS")

            self._httpd = ThreadingHTTPServer((self.bind_addr, self.port), Handler)
            self._httpd.daemon_threads = True
            threading.Thread(target=self._httpd.serve_forever, daemon=True, name="lab-http").start()
        logger.info("lab HTTP server started", extra={"lab_bind": f"{self.bind_addr}:{self.port}"})

    def stop(self) -> None:
        with self._lock:
            if self._httpd:
                self._httpd.shutdown()
                self._httpd.server_close()
                self._httpd = None

    @property
    def running(self) -> bool:
        return self._httpd is not None

    # ------------------------------------------------------------------
    def _handle(self, handler: BaseHTTPRequestHandler, method: str) -> None:
        host = handler.headers.get("Host")
        target = handler.path
        length = int(handler.headers.get("Content-Length") or 0)
        if length:
            try:
                handler.rfile.read(length)
            except Exception:
                pass
        route = self.find_route(host, target)
        status = route.status if route else 404
        body = route.body if route else b"Not Found"
        headers = dict(route.headers) if route else {}
        entry = HttpLogEntry(
            timestamp=self.clock.now().isoformat(),
            client=handler.client_address[0],
            method=method,
            target=target,
            host=host,
            status=status,
            headers={
                k: v for k, v in handler.headers.items()
                if k.lower() in {"user-agent", "content-length", "connection", "upgrade",
                                 "origin", "referer", "cookie", "authorization", "set-cookie"}
            },
            route=f"{route.host}{route.path}" if route else None,
            set_cookies=[cookie.header() for cookie in route.cookies] if route else [],
        )
        self.log.append(entry)
        if self.evidence is not None:
            entry.evidence_ref = self._record_evidence(entry)
        self._emit(entry)

        if "websocket" in (handler.headers.get("Upgrade") or "").lower():
            self._websocket_handshake(handler, host or "")
            return

        handler.send_response(status)
        handler.send_header("Content-Type", route.content_type if route else "text/plain")
        handler.send_header("Content-Length", str(len(body)))
        for key, value in headers.items():
            handler.send_header(key, value)
        if route:
            for cookie in route.cookies:
                handler.send_header("Set-Cookie", cookie.header())
        handler.end_headers()
        if method != "HEAD":
            handler.wfile.write(body)

    def _websocket_handshake(self, handler: BaseHTTPRequestHandler, host: str) -> None:
        key = handler.headers.get("Sec-WebSocket-Key")
        if not key:
            handler.send_response(400)
            handler.end_headers()
            return
        accept = base64.b64encode(hashlib.sha1((key + _WS_GUID).encode()).digest()).decode()
        handler.send_response(101, "Switching Protocols")
        handler.send_header("Upgrade", "websocket")
        handler.send_header("Connection", "Upgrade")
        handler.send_header("Sec-WebSocket-Accept", accept)
        handler.end_headers()
        self._emit_ws_event(host, "handshake")
        try:
            while True:
                frame = _read_ws_frame(handler.connection)
                if frame is None:
                    break
                opcode, payload = frame
                self._emit_ws_event(host, f"frame opcode={opcode} len={len(payload)}")
                if opcode == 0x8:  # close
                    handler.connection.sendall(_build_ws_frame(0x8, b""))
                    break
                if opcode in (0x1, 0x2, 0x9):
                    reply = payload if opcode == 0x9 else b"lab-echo:" + payload
                    handler.connection.sendall(_build_ws_frame(0x1 if opcode != 0x9 else 0xA, reply))
        except (ConnectionError, OSError):
            return

    # ------------------------------------------------------------------
    def _record_evidence(self, entry: HttpLogEntry) -> str | None:
        import json

        try:
            record = self.evidence.record_text(
                json.dumps(entry.__dict__, indent=2, default=str),
                kind="http_exchange", name=f"http-{entry.client}-{len(self.log)}.json",
                sub="http", test_id=self.test_id, scenario_id=self.scenario_id,
                metadata={"host": entry.host, "method": entry.method, "target": entry.target},
            )
            return record.evidence_id
        except Exception:
            logger.exception("failed to record HTTP exchange evidence")
            return None

    def _emit(self, entry: HttpLogEntry) -> None:
        if self.bus is None:
            return
        self.bus(
            make_event(
                session_id=self.session_id,
                category=EventCategory.HTTP,
                source=EventSource.LAB_SERVER,
                severity=EventSeverity.NOTICE if entry.status and entry.status >= 400 else EventSeverity.INFO,
                summary=f"lab HTTP {entry.method} {entry.target} host={entry.host} -> {entry.status}",
                protocol="http",
                dst_addr=entry.client,
                dst_port=self.port,
                details={
                    "method": entry.method,
                    "target": entry.target,
                    "host": entry.host,
                    "status": entry.status,
                    "headers": entry.headers,
                    "route": entry.route,
                    "set_cookies": list(entry.set_cookies),
                    "evidence_ref": entry.evidence_ref,
                    "lab_server": True,
                },
                device_id=self.device_id,
            )
        )

    def _emit_ws_event(self, host: str, action: str) -> None:
        if self.bus is None:
            return
        self.bus(
            make_event(
                session_id=self.session_id,
                category=EventCategory.HTTP,
                source=EventSource.LAB_SERVER,
                severity=EventSeverity.INFO,
                summary=f"lab WebSocket {action} host={host}",
                protocol="websocket",
                details={"host": host, "action": action, "lab_server": True},
                device_id=self.device_id,
            )
        )

    def export_log(self) -> list[dict]:
        return [
            {
                "timestamp": e.timestamp, "client": e.client, "method": e.method,
                "target": e.target, "host": e.host, "status": e.status,
                "headers": e.headers, "route": e.route,
            }
            for e in self.log
        ]


def _read_ws_frame(sock: socket.socket) -> tuple[int, bytes] | None:
    header = _recv_exact(sock, 2)
    if header is None:
        return None
    opcode = header[0] & 0x0F
    masked = bool(header[1] & 0x80)
    length = header[1] & 0x7F
    if length == 126:
        ext = _recv_exact(sock, 2)
        if ext is None:
            return None
        length = struct.unpack("!H", ext)[0]
    elif length == 127:
        ext = _recv_exact(sock, 8)
        if ext is None:
            return None
        length = struct.unpack("!Q", ext)[0]
    mask = _recv_exact(sock, 4) if masked else None
    payload = _recv_exact(sock, length) if length else b""
    if payload is None:
        return None
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload


def _recv_exact(sock: socket.socket, count: int) -> bytes | None:
    chunks = bytearray()
    while len(chunks) < count:
        try:
            chunk = sock.recv(count - len(chunks))
        except OSError:
            return None
        if not chunk:
            return None
        chunks.extend(chunk)
    return bytes(chunks)


def _build_ws_frame(opcode: int, payload: bytes) -> bytes:
    header = bytearray([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header.append(length)
    elif length < 65536:
        header.append(126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(127)
        header.extend(struct.pack("!Q", length))
    return bytes(header) + payload
