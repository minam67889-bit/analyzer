"""Unified network/security event model.

Every observation from every source is normalized into a :class:`NetworkEvent`. Events are
immutable, timestamped (UTC), and carry correlation identifiers for session, test,
scenario and device.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from ..clock import Clock, SystemClock
from ..ids import new_id


class EventCategory(str, Enum):
    PACKET = "packet"
    CONNECTION = "connection"
    DNS = "dns"
    DHCP = "dhcp"
    ARP = "arp"
    IPV6_NEIGHBOR = "ipv6_neighbor"
    TLS = "tls"
    HTTP = "http"
    QUIC = "quic"
    VPN_STATE = "vpn_state"
    ROUTE_STATE = "route_state"
    GATEWAY_STATE = "gateway_state"
    FIREWALL = "firewall"
    APP = "app"
    LAB_SERVER = "lab_server"
    SYSTEM = "system"
    TEST = "test"
    SCENARIO = "scenario"
    SECURITY_ALERT = "security_alert"


class EventSeverity(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ALERT = "alert"
    CRITICAL = "critical"


class EventSource(str, Enum):
    WINDOWS_HOST = "windows_host"
    ANDROID_DEVICE = "android_device"
    LAB_SERVER = "lab_server"
    PACKET_CAPTURE = "packet_capture"
    FIREWALL = "firewall"
    TEST_ENGINE = "test_engine"
    ORCHESTRATOR = "orchestrator"
    INFRASTRUCTURE = "infrastructure"
    USER = "user"


_SEVERITY_ORDER = {s: i for i, s in enumerate(EventSeverity)}


@dataclass(frozen=True, slots=True)
class NetworkEvent:
    event_id: str
    timestamp: datetime
    category: EventCategory
    source: EventSource
    severity: EventSeverity
    summary: str
    session_id: str
    test_id: str | None = None
    scenario_id: str | None = None
    device_id: str | None = None
    protocol: str | None = None
    src_addr: str | None = None
    dst_addr: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    details: Mapping[str, Any] = field(default_factory=dict)
    evidence_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.astimezone(UTC).isoformat()
        data["category"] = self.category.value
        data["source"] = self.source.value
        data["severity"] = self.severity.value
        data["details"] = dict(self.details)
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> NetworkEvent:
        return cls(
            event_id=str(data["event_id"]),
            timestamp=datetime.fromisoformat(str(data["timestamp"])),
            category=EventCategory(data["category"]),
            source=EventSource(data["source"]),
            severity=EventSeverity(data["severity"]),
            summary=str(data["summary"]),
            session_id=str(data["session_id"]),
            test_id=data.get("test_id"),
            scenario_id=data.get("scenario_id"),
            device_id=data.get("device_id"),
            protocol=data.get("protocol"),
            src_addr=data.get("src_addr"),
            dst_addr=data.get("dst_addr"),
            src_port=data.get("src_port"),
            dst_port=data.get("dst_port"),
            details=dict(data.get("details") or {}),
            evidence_ref=data.get("evidence_ref"),
        )


def make_event(
    *,
    session_id: str,
    category: EventCategory,
    source: EventSource,
    summary: str,
    severity: EventSeverity = EventSeverity.INFO,
    clock: Clock | None = None,
    test_id: str | None = None,
    scenario_id: str | None = None,
    device_id: str | None = None,
    protocol: str | None = None,
    src_addr: str | None = None,
    dst_addr: str | None = None,
    src_port: int | None = None,
    dst_port: int | None = None,
    details: Mapping[str, Any] | None = None,
    evidence_ref: str | None = None,
    event_id: str | None = None,
) -> NetworkEvent:
    clock = clock or SystemClock()
    return NetworkEvent(
        event_id=event_id or new_id("evt"),
        timestamp=clock.now(),
        category=category,
        source=source,
        severity=severity,
        summary=summary,
        session_id=session_id,
        test_id=test_id,
        scenario_id=scenario_id,
        device_id=device_id,
        protocol=protocol,
        src_addr=src_addr,
        dst_addr=dst_addr,
        src_port=src_port,
        dst_port=dst_port,
        details=dict(details or {}),
        evidence_ref=evidence_ref,
    )


def severity_at_least(a: EventSeverity, b: EventSeverity) -> bool:
    return _SEVERITY_ORDER[a] >= _SEVERITY_ORDER[b]


def dumps_event(event: NetworkEvent) -> str:
    return json.dumps(event.to_dict(), sort_keys=True)
