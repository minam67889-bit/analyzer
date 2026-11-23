"""Capability model and probing.

A capability is never assumed. ``CapabilitySet.require`` raises a structured error that
the planner converts into an ``UNSUPPORTED`` coverage row with the exact reason.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum

from ..errors import CapabilityError


class Capability(str, Enum):
    WIFI_HOTSPOT = "wifi_hotspot"
    WIFI_HOSTED_NETWORK = "wifi_hosted_network"
    WIFI_MONITOR_MODE = "wifi_monitor_mode"
    WIFI_INJECTION = "wifi_injection"
    WIFI_PMF = "wifi_pmf"
    PACKET_CAPTURE = "packet_capture"
    RAW_80211 = "raw_80211"
    WFP_USER_MODE = "wfp_user_mode"
    WFP_CALLOUT = "wfp_callout"
    ADB = "adb"
    ANDROID_ROOT = "android_root"
    FIREWALL_API = "firewall_api"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    EXTERNAL_AP = "external_ap"
    HOSTAPD = "hostapd"
    HYPER_V = "hyper_v"
    TSHARK = "tshark"
    NETSH = "netsh"
    POWERSHELL = "powershell"
    LAB_CA = "lab_ca"
    LOOPBACK_CAPTURE = "loopback_capture"
    TLS_INTERCEPTION = "tls_interception"


@dataclass(frozen=True)
class CapabilityReport:
    capability: Capability
    available: bool
    reason: str = ""
    prerequisites: tuple[str, ...] = ()
    backend: str = ""
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "capability": self.capability.value,
            "available": self.available,
            "reason": self.reason,
            "prerequisites": list(self.prerequisites),
            "backend": self.backend,
            "raw": dict(self.raw),
        }


class CapabilitySet:
    def __init__(self, reports: Iterable[CapabilityReport] = ()) -> None:
        self._reports: dict[Capability, CapabilityReport] = {r.capability: r for r in reports}

    def add(self, report: CapabilityReport) -> None:
        self._reports[report.capability] = report

    def is_available(self, capability: Capability) -> bool:
        report = self._reports.get(capability)
        return bool(report and report.available)

    def reason(self, capability: Capability) -> str:
        report = self._reports.get(capability)
        if report is None:
            return "capability was not probed"
        return report.reason or ("available" if report.available else "unavailable")

    def require(self, *capabilities: Capability) -> None:
        missing = [c for c in capabilities if not self.is_available(c)]
        if missing:
            detail = "; ".join(f"{c.value}: {self.reason(c)}" for c in missing)
            raise CapabilityError(f"missing required capability/capabilities: {detail}")

    def missing(self, capabilities: Iterable[Capability]) -> list[Capability]:
        return [c for c in capabilities if not self.is_available(c)]

    def to_dict(self) -> dict:
        return {c.value: r.to_dict() for c, r in sorted(self._reports.items())}

    def __iter__(self):
        return iter(self._reports.values())
