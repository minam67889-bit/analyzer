"""Laboratory DHCPv4 server with rogue-configuration support.

Binds to the lab interface and answers only the authorized device MAC (unless explicitly
configured otherwise). Every message is logged and published as an event. The same server
can act as a rogue DHCP server by supplying attacker ``router``/``dns_servers`` values,
which is how the DHCP-spoofing scenario is realized.
"""

from __future__ import annotations

import ipaddress
import socketserver
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from ..clock import Clock, SystemClock
from ..core.events import EventCategory, EventSeverity, EventSource, make_event
from ..logging_config import get_logger
from ..protocols import dhcp

logger = get_logger(__name__)


@dataclass
class Lease:
    mac: str
    ip: str
    hostname: str | None
    lease_time: int
    offered_at: str


@dataclass
class DhcpServerConfig:
    bind_addr: str = "0.0.0.0"
    port: int = 67
    server_id: str = "10.10.0.1"
    subnet_mask: str = "255.255.255.0"
    router: str = "10.10.0.1"
    dns_servers: list[str] = field(default_factory=lambda: ["10.10.0.1"])
    lease_time: int = 3600
    pool_start: str = "10.10.0.50"
    pool_end: str = "10.10.0.200"
    allowed_macs: set[str] = field(default_factory=set)
    hostname_anonymous: bool = False


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: DhcpServer = self.server  # type: ignore[assignment]
        data = self.request[0]
        sock = self.request[1]
        try:
            response, dest = server.handle_message(data)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("dhcp handling failed: %s", exc)
            return
        if response is not None:
            try:
                sock.sendto(response, dest)
            except OSError as exc:
                logger.warning("dhcp send failed: %s", exc)


class _DhcpServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class DhcpServer:
    def __init__(
        self,
        config: DhcpServerConfig | None = None,
        *,
        bus: Callable[..., None] | None = None,
        clock: Clock | None = None,
        session_id: str = "",
        device_id: str | None = None,
    ) -> None:
        self.config = config or DhcpServerConfig()
        self.bus = bus
        self.clock = clock or SystemClock()
        self.session_id = session_id
        self.device_id = device_id
        self.leases: dict[str, Lease] = {}
        self.message_log: list[dict] = []
        self._server: _DhcpServer | None = None
        self._lock = threading.RLock()
        self._allocated: set[str] = set()
        self._pool = self._build_pool()

    def _build_pool(self) -> list[str]:
        start = int(ipaddress.ip_address(self.config.pool_start))
        end = int(ipaddress.ip_address(self.config.pool_end))
        return [str(ipaddress.ip_address(i)) for i in range(start, end + 1)]

    # ------------------------------------------------------------------
    def start(self) -> None:
        with self._lock:
            if self._server:
                return
            self._server = _DhcpServer((self.config.bind_addr, self.config.port), _Handler)
            self._server.daemon_threads = True
            threading.Thread(target=self._server.serve_forever, daemon=True, name="dhcp").start()
        logger.info("DHCP server started", extra={"lab_bind": f"{self.config.bind_addr}:{self.config.port}"})

    def stop(self) -> None:
        with self._lock:
            if self._server:
                self._server.shutdown()
                self._server.server_close()
                self._server = None

    @property
    def running(self) -> bool:
        return self._server is not None

    # ------------------------------------------------------------------
    def handle_message(self, data: bytes) -> tuple[bytes | None, tuple[str, int]]:
        msg = dhcp.parse_message(data)
        mac = msg.client_mac()
        if self.config.allowed_macs and mac not in self.config.allowed_macs:
            self._emit(msg, "ignored", None)
            return None, ("255.255.255.255", 68)

        msg_type = msg.msg_type
        hostname = None
        if not self.config.hostname_anonymous:
            raw = msg.get(dhcp.OPT_HOSTNAME)
            hostname = raw.decode("utf-8", "replace") if raw else None

        if msg_type == dhcp.MSGTYPE_DISCOVER:
            offered = self._lease_for(mac)
            response = dhcp.make_offer(
                msg, server_id=self.config.server_id, offered_ip=offered,
                subnet_mask=self.config.subnet_mask, router=self.config.router,
                dns_servers=self.config.dns_servers, lease_time=self.config.lease_time,
                hostname=hostname,
            )
            self._emit(msg, "offer", response.yiaddr)
            return dhcp.build_message(response), ("255.255.255.255", 68)

        if msg_type == dhcp.MSGTYPE_REQUEST:
            requested = msg.get(dhcp.OPT_REQUESTED_IP)
            ip = ".".join(str(b) for b in requested) if requested else self._lease_for(mac)
            if self._is_pool_ip(ip):
                self._commit(mac, ip, hostname)
                response = dhcp.make_ack(
                    msg, server_id=self.config.server_id, offered_ip=ip,
                    subnet_mask=self.config.subnet_mask, router=self.config.router,
                    dns_servers=self.config.dns_servers, lease_time=self.config.lease_time,
                )
                self._emit(msg, "ack", ip)
                return dhcp.build_message(response), ("255.255.255.255", 68)
            response = dhcp.make_nak(msg, server_id=self.config.server_id)
            self._emit(msg, "nak", None)
            return dhcp.build_message(response), ("255.255.255.255", 68)

        if msg_type == dhcp.MSGTYPE_RELEASE:
            self.leases.pop(mac, None)
            self._emit(msg, "release", None)
            return None, ("255.255.255.255", 67)

        self._emit(msg, "ignored", None)
        return None, ("255.255.255.255", 68)

    def _lease_for(self, mac: str) -> str:
        lease = self.leases.get(mac)
        if lease:
            return lease.ip
        for ip in self._pool:
            if ip not in self._allocated:
                return ip
        return self.config.pool_start

    def _commit(self, mac: str, ip: str, hostname: str | None) -> None:
        self._allocated.add(ip)
        self.leases[mac] = Lease(
            mac=mac, ip=ip, hostname=hostname,
            lease_time=self.config.lease_time, offered_at=self.clock.now().isoformat(),
        )

    def _is_pool_ip(self, ip: str) -> bool:
        try:
            value = int(ipaddress.ip_address(ip))
        except ValueError:
            return False
        return int(ipaddress.ip_address(self.config.pool_start)) <= value <= int(
            ipaddress.ip_address(self.config.pool_end)
        )

    def _emit(self, msg: dhcp.DhcpMessage, action: str, yiaddr: str | None) -> None:
        record = {
            "timestamp": self.clock.now().isoformat(),
            "action": action,
            "msg_type": msg.msg_type_name,
            "mac": msg.client_mac(),
            "ciaddr": msg.ciaddr,
            "yiaddr": yiaddr or msg.yiaddr,
            "server_id": self.config.server_id,
            "router": self.config.router,
            "dns_servers": list(self.config.dns_servers),
        }
        self.message_log.append(record)
        if self.bus is None:
            return
        self.bus(
            make_event(
                session_id=self.session_id,
                category=EventCategory.DHCP,
                source=EventSource.LAB_SERVER,
                severity=EventSeverity.NOTICE if action in {"offer", "ack", "nak"} else EventSeverity.INFO,
                summary=f"lab DHCP {action} mac={msg.client_mac()} yiaddr={yiaddr or '-'}",
                protocol="dhcp",
                dst_addr=msg.client_mac(),
                details=record,
                device_id=self.device_id,
            )
        )

    def export_log(self) -> list[dict]:
        return list(self.message_log)
