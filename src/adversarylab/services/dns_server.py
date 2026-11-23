"""Laboratory DNS server (UDP/TCP 53) with configurable zone and spoofing.

The server is intentionally small and fully observable: every query and synthesized answer
is published as a :class:`NetworkEvent` and recorded in an in-memory query log that is
exported as evidence. It supports:
- static zones with configurable TTL,
- a pluggable responder for spoofing/rebinding/timed behavior,
- selective NXDOMAIN, SERVFAIL, REFUSED, and silent drops,
- TCP transport (RFC 7766) for the same policy.
"""

from __future__ import annotations

import socketserver
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from ..clock import Clock, SystemClock
from ..core.events import EventCategory, EventSeverity, EventSource, make_event
from ..logging_config import get_logger
from ..protocols import dns

logger = get_logger(__name__)

Responder = Callable[[dns.DnsQuestion, dns.DnsMessage], list[dns.DnsRecord] | None]
EventSink = Callable[..., None]


@dataclass
class DnsQueryRecord:
    timestamp: str
    transport: str
    client: str
    client_port: int
    qname: str
    qtype: int
    rcode: int
    answers: list[dict]
    action: str

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "transport": self.transport,
            "client": self.client,
            "client_port": self.client_port,
            "qname": self.qname,
            "qtype": self.qtype,
            "rcode": self.rcode,
            "answers": self.answers,
            "action": self.action,
        }


@dataclass
class DnsServerConfig:
    bind_addr: str = "0.0.0.0"
    port: int = 53
    zone: dict[str, list[dns.DnsRecord]] = field(default_factory=dict)
    default_ttl: int = 60
    nxdomain_names: set[str] = field(default_factory=set)
    drop_names: set[str] = field(default_factory=set)
    refuse_names: set[str] = field(default_factory=set)
    responder: Responder | None = None
    allow_client: Callable[[str], bool] | None = None
    serve_tcp: bool = True


class _UdpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: DnsServer = getattr(self.server, "lab_dns", None)  # type: ignore[assignment]
        if server is None:
            return
        data = self.request[0]
        sock = self.request[1]
        client = self.client_address[0]
        try:
            response = server.handle_query(data, client, "udp")
        except Exception as exc:  # never let a malformed packet kill the server
            logger.warning("dns udp handling failed: %s", exc)
            return
        if response is not None:
            sock.sendto(response, self.client_address)


class _TcpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: DnsServer = getattr(self.server, "lab_dns", None)  # type: ignore[assignment]
        if server is None:
            return
        client = self.client_address[0]
        try:
            while True:
                header = self._read_exact(2)
                if header is None:
                    return
                length = struct.unpack("!H", header)[0]
                data = self._read_exact(length)
                if data is None:
                    return
                response = server.handle_query(data, client, "tcp")
                if response is None:
                    continue
                self.request.sendall(struct.pack("!H", len(response)) + response)
        except (ConnectionError, OSError):
            return
        except Exception as exc:  # pragma: no cover
            logger.warning("dns tcp handling failed: %s", exc)

    def _read_exact(self, count: int) -> bytes | None:
        chunks = bytearray()
        while len(chunks) < count:
            try:
                chunk = self.request.recv(count - len(chunks))
            except OSError:
                return None
            if not chunk:
                return None
            chunks.extend(chunk)
        return bytes(chunks)


class _UdpServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class _TcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class DnsServer:
    def __init__(
        self,
        config: DnsServerConfig | None = None,
        *,
        bus: EventSink | None = None,
        clock: Clock | None = None,
        session_id: str = "",
        device_id: str | None = None,
    ) -> None:
        self.config = config or DnsServerConfig()
        self.bus = bus
        self.clock = clock or SystemClock()
        self.session_id = session_id
        self.device_id = device_id
        self.query_log: list[DnsQueryRecord] = []
        self._udp: _UdpServer | None = None
        self._tcp: _TcpServer | None = None
        self._lock = threading.RLock()
        self._running = False

    # ------------------------------------------------------------------
    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._udp = _UdpServer((self.config.bind_addr, self.config.port), _UdpHandler)
            self._udp.daemon_threads = True
            self._udp.lab_dns = self  # type: ignore[attr-defined]
            threading.Thread(target=self._udp.serve_forever, daemon=True, name="dns-udp").start()
            if self.config.serve_tcp:
                self._tcp = _TcpServer((self.config.bind_addr, self.config.port), _TcpHandler)
                self._tcp.daemon_threads = True
                self._tcp.lab_dns = self  # type: ignore[attr-defined]
                self._tcp.lab_dns = self  # type: ignore[attr-defined]
                threading.Thread(target=self._tcp.serve_forever, daemon=True, name="dns-tcp").start()
            self._running = True
        logger.info("DNS server started", extra={"lab_bind": f"{self.config.bind_addr}:{self.config.port}"})

    def stop(self) -> None:
        with self._lock:
            if self._udp:
                self._udp.shutdown()
                self._udp.server_close()
                self._udp = None
            if self._tcp:
                self._tcp.shutdown()
                self._tcp.server_close()
                self._tcp = None
            self._running = False

    @property
    def running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    def add_record(self, name: str, record: dns.DnsRecord) -> None:
        self.config.zone.setdefault(name.rstrip(".").lower(), []).append(record)

    def set_zone(self, zone: dict[str, list[dns.DnsRecord]]) -> None:
        self.config.zone = {k.rstrip(".").lower(): v for k, v in zone.items()}

    # ------------------------------------------------------------------
    def handle_query(self, data: bytes, client: str, transport: str) -> bytes | None:
        if self.config.allow_client is not None and not self.config.allow_client(client):
            self._emit(client, transport, "dropped", None, dns.RCODE_REFUSED, [], "client-not-authorized")
            return None
        try:
            query = dns.parse_message(data)
        except dns.DnsError:
            return None
        if not query.questions:
            return None
        question = query.questions[0]
        name = question.name.rstrip(".").lower()
        action = "answered"
        answers: list[dns.DnsRecord] = []
        rcode = dns.RCODE_NOERROR

        if name in self.config.drop_names:
            self._emit(client, transport, "dropped", query, dns.RCODE_NOERROR, [], "drop")
            return None
        if name in self.config.refuse_names:
            rcode = dns.RCODE_REFUSED
            action = "refused"
        elif name in self.config.nxdomain_names:
            rcode = dns.RCODE_NXDOMAIN
            action = "nxdomain"
        else:
            if self.config.responder is not None:
                try:
                    answers = self.config.responder(question, query) or []
                    action = "spoofed" if answers else "answered"
                except Exception:
                    answers = []
                    action = "responder-error"
            if not answers and not rcode:
                answers = self.config.zone.get(name, [])

        response = dns.make_response(query, answers, rcode=rcode, aa=True)
        self._emit(client, transport, action, query, response.rcode, answers, name)
        return dns.build_message(response)

    # ------------------------------------------------------------------
    def _emit(
        self,
        client: str,
        transport: str,
        action: str,
        query: dns.DnsMessage | None,
        rcode: int,
        answers: list[dns.DnsRecord],
        name: str,
    ) -> None:
        now = self.clock.now()
        qtype = query.questions[0].qtype if query and query.questions else 0
        answer_dicts = [
            {"name": a.name, "type": a.rtype, "ttl": a.ttl, "address": a.address, "cname": a.cname}
            for a in answers
        ]
        record = DnsQueryRecord(
            timestamp=now.isoformat(),
            transport=transport,
            client=client,
            client_port=0,
            qname=name,
            qtype=qtype,
            rcode=rcode,
            answers=answer_dicts,
            action=action,
        )
        self.query_log.append(record)
        if self.bus is None:
            return
        self.bus(
            make_event(
                session_id=self.session_id,
                category=EventCategory.DNS,
                source=EventSource.LAB_SERVER,
                severity=EventSeverity.NOTICE if action in {"spoofed", "dropped", "refused"} else EventSeverity.INFO,
                summary=f"lab DNS {action} {name} -> {[a.get('address') or a.get('cname') for a in answer_dicts]}",
                protocol="dns",
                dst_addr=client,
                src_addr=self.config.bind_addr,
                details={
                    "qname": name,
                    "qtype": qtype,
                    "rcode": rcode,
                    "action": action,
                    "transport": transport,
                    "answers": answer_dicts,
                    "lab_server": True,
                },
                device_id=self.device_id,
            )
        )

    def export_log(self) -> list[dict]:
        return [r.to_dict() for r in self.query_log]
