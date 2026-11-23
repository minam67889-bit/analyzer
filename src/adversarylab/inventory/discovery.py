"""Destination inventory built from observed DNS answers, connections and server hits.

The inventory is updated continuously while passive monitoring is active. It separates
*discovery* (passive) from *testing* (active): only destinations classified as lab-owned
become active test candidates.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from ..clock import Clock, SystemClock
from ..core.events import EventCategory, NetworkEvent
from ..ids import new_id
from ..logging_config import get_logger
from .ownership import OwnershipPolicy, OwnershipStatus

logger = get_logger(__name__)

_WELL_KNOWN_PORTS = {
    80: "http",
    443: "https",
    853: "dot",
    53: "dns",
    67: "dhcp",
    22: "ssh",
    8080: "http-alt",
}


@dataclass
class Destination:
    destination_id: str
    session_id: str
    host: str | None
    ip: str | None
    port: int | None
    protocol: str | None
    family: str | None
    ownership: str
    ownership_reason: str
    discovered_by: str
    service_guess: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    active: bool = True
    tags: list[str] = field(default_factory=list)
    hit_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ("first_seen", "last_seen"):
            value = getattr(self, key)
            data[key] = value.isoformat() if value else None
        return data

    @property
    def label(self) -> str:
        host = self.host or self.ip or "?"
        return f"{host}:{self.port}" if self.port else host


class DestinationInventory:
    def __init__(self, session_id: str, policy: OwnershipPolicy, clock: Clock | None = None) -> None:
        self.session_id = session_id
        self.policy = policy
        self.clock = clock or SystemClock()
        self._destinations: dict[str, Destination] = {}
        self._by_ip: dict[str, str] = {}

    # ------------------------------------------------------------------
    def _key(self, ip: str | None, port: int | None, protocol: str | None) -> str:
        return f"{ip or ''}|{port or ''}|{protocol or ''}"

    def _upsert(
        self,
        *,
        host: str | None,
        ip: str | None,
        port: int | None,
        protocol: str | None,
        discovered_by: str,
        family: str | None = None,
    ) -> Destination:
        key = self._key(ip, port, protocol)
        existing = self._destinations.get(key)
        now = self.clock.now()
        if existing is not None:
            existing.last_seen = now
            existing.hit_count += 1
            if host and not existing.host:
                existing.host = host
            if ip and not existing.ip:
                existing.ip = ip
            return existing

        # Associate a connection with a host previously learned from DNS for the same IP.
        if host is None and ip and ip in self._by_ip:
            host = self._destinations[self._by_ip[ip]].host
        decision = self.policy.classify(host, ip)
        ownership, reason = decision.status, decision.reason
        service = None
        if port and protocol in {None, "tcp", "udp"}:
            service = _WELL_KNOWN_PORTS.get(port)
        if protocol in {"http", "https", "dot", "quic", "dns"} and service is None:
            service = protocol
        dest = Destination(
            destination_id=new_id("dst"),
            session_id=self.session_id,
            host=host,
            ip=ip,
            port=port,
            protocol=protocol,
            family=family or _family_of(ip),
            ownership=ownership.value,
            ownership_reason=reason,
            discovered_by=discovered_by,
            service_guess=service,
            first_seen=now,
            last_seen=now,
            hit_count=1,
        )
        self._destinations[key] = dest
        if ip:
            self._by_ip[ip] = key
        logger.info(
            "destination discovered",
            extra={"lab_destination": dest.label, "lab_ownership": dest.ownership},
        )
        return dest

    # ------------------------------------------------------------------
    def record_dns_answer(self, name: str, ip: str, *, discovered_by: str = "dns") -> Destination:
        return self._upsert(host=name, ip=ip, port=None, protocol="dns", discovered_by=discovered_by)

    def record_connection(
        self,
        *,
        host: str | None = None,
        ip: str | None,
        port: int | None,
        protocol: str | None = "tcp",
        discovered_by: str = "capture",
    ) -> Destination:
        return self._upsert(
            host=host, ip=ip, port=port, protocol=protocol, discovered_by=discovered_by
        )

    def record_http_host(self, host: str, ip: str | None, port: int = 80) -> Destination:
        return self._upsert(
            host=host, ip=ip, port=port, protocol="http", discovered_by="http"
        )

    def record_server_hit(self, host: str, ip: str, port: int, protocol: str) -> Destination:
        return self._upsert(
            host=host, ip=ip, port=port, protocol=protocol, discovered_by="lab_server"
        )

    # ------------------------------------------------------------------
    def get(self, ip: str) -> Destination | None:
        key = self._by_ip.get(ip)
        return self._destinations.get(key) if key else None

    def all(self) -> list[Destination]:
        return sorted(self._destinations.values(), key=lambda d: d.last_seen or datetime.min)

    def by_ownership(self, *statuses: OwnershipStatus) -> list[Destination]:
        wanted = {s.value for s in statuses}
        return [d for d in self.all() if d.ownership in wanted]

    def active_targets(self) -> list[Destination]:
        """Destinations that may be actively tested (lab-owned only)."""
        return self.by_ownership(OwnershipStatus.LAB_OWNED, OwnershipStatus.LAB_INFRA)

    def external_destinations(self) -> list[Destination]:
        return self.by_ownership(OwnershipStatus.EXTERNAL, OwnershipStatus.UNKNOWN)

    def service_ports(self) -> dict[int, int]:
        counts: dict[int, int] = {}
        for dest in self._destinations.values():
            if dest.port:
                counts[dest.port] = counts.get(dest.port, 0) + dest.hit_count
        return dict(sorted(counts.items()))


def _family_of(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return "ipv6" if addr.version == 6 else "ipv4"


class DiscoveryEngine:
    """Consumes normalized events and maintains a DestinationInventory."""

    def __init__(
        self,
        inventory: DestinationInventory,
        *,
        db: Any | None = None,
        bus: Any | None = None,
    ) -> None:
        self.inventory = inventory
        self.db = db
        self.bus = bus
        if bus is not None:
            bus.subscribe(self.on_event)

    def on_event(self, event: NetworkEvent) -> None:
        details = event.details or {}
        if event.category is EventCategory.DNS:
            name = str(details.get("qname") or details.get("name") or "")
            answers = details.get("answers") or []
            if isinstance(answers, str):
                answers = [answers]
            for answer in answers:
                if isinstance(answer, str) and _looks_like_ip(answer):
                    dest = self.inventory.record_dns_answer(name, answer)
                    self._persist(dest)
        elif event.category is EventCategory.CONNECTION:
            ip = event.dst_addr or str(details.get("dst") or "")
            port = event.dst_port or details.get("dst_port")
            host = details.get("host")
            if ip:
                dest = self.inventory.record_connection(
                    host=host if isinstance(host, str) else None,
                    ip=ip,
                    port=int(port) if port else None,
                    protocol=event.protocol,
                )
                self._persist(dest)
        elif event.category is EventCategory.HTTP:
            host = str(details.get("host") or "")
            ip = event.dst_addr
            port = event.dst_port or 80
            if host or ip:
                dest = self.inventory.record_http_host(host, ip, int(port or 80))
                self._persist(dest)

    def _persist(self, dest: Destination) -> None:
        if self.db is None:
            return
        row = dest.to_dict()
        row["first_seen"] = dest.first_seen.isoformat() if dest.first_seen else None
        row["last_seen"] = dest.last_seen.isoformat() if dest.last_seen else None
        self.db.upsert_destination(row)


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
