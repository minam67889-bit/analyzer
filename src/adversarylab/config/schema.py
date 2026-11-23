"""Typed configuration schema with semantic validation."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from ..errors import ValidationError

_BACKENDS = {"auto", "winrt_hotspot", "hosted_network", "external_ap", "hostapd"}
_BANDS = {"2.4GHz", "5GHz", "6GHz", "auto"}


@dataclass
class ScopeConfig:
    domain_roots: list[str] = field(default_factory=lambda: ["lab.test", "lab.local"])
    wildcard_subdomains: list[str] = field(default_factory=lambda: ["*.lab.test"])
    ip_ranges: list[str] = field(default_factory=lambda: ["10.10.0.0/16"])
    lab_subnets: list[str] = field(default_factory=lambda: ["10.10.0.0/16"])
    lab_infra_addresses: list[str] = field(default_factory=lambda: ["10.10.0.1"])
    deny_egress_by_default: bool = True

    def validate(self) -> None:
        for name in ("domain_roots", "wildcard_subdomains"):
            for value in getattr(self, name):
                if not value or not isinstance(value, str):
                    raise ValidationError(f"scope.{name} entries must be non-empty strings")
        for name in ("ip_ranges", "lab_subnets"):
            for value in getattr(self, name):
                try:
                    ipaddress.ip_network(value, strict=False)
                except ValueError as exc:
                    raise ValidationError(f"scope.{name}: invalid network {value!r}: {exc}") from exc
        for value in self.lab_infra_addresses:
            try:
                ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValidationError(
                    f"scope.lab_infra_addresses: invalid address {value!r}: {exc}"
                ) from exc


@dataclass
class InfrastructureConfig:
    backend: str = "auto"
    adapter_hint: str = ""
    ssid: str = "AdversaryLab"
    passphrase: str = ""
    band: str = "auto"
    channel: int = 36
    ipv4_subnet: str = "10.10.0.0/24"
    ipv4_gateway: str = "10.10.0.1"
    ipv4_dhcp_start: str = "10.10.0.50"
    ipv4_dhcp_end: str = "10.10.0.200"
    ipv6_prefix: str = "fd00:1234::/64"
    ipv6_gateway: str = "fd00:1234::1"
    isolation: bool = True
    egress_allow: list[str] = field(default_factory=lambda: ["10.10.0.0/16"])

    def validate(self) -> None:
        if self.backend not in _BACKENDS:
            raise ValidationError(f"infrastructure.backend must be one of {sorted(_BACKENDS)}")
        if self.band not in _BANDS:
            raise ValidationError(f"infrastructure.band must be one of {sorted(_BANDS)}")
        if not (1 <= self.channel <= 196):
            raise ValidationError("infrastructure.channel out of range")
        if not self.ssid or len(self.ssid) > 32:
            raise ValidationError("infrastructure.ssid must be 1..32 characters")
        if self.passphrase and not (8 <= len(self.passphrase) <= 63):
            raise ValidationError("infrastructure.passphrase must be 8..63 characters if set")
        for name in ("ipv4_subnet",):
            try:
                ipaddress.ip_network(getattr(self, name), strict=False)
            except ValueError as exc:
                raise ValidationError(f"infrastructure.{name}: {exc}") from exc
        for name in ("ipv4_gateway", "ipv4_dhcp_start", "ipv4_dhcp_end"):
            try:
                ipaddress.ip_address(getattr(self, name))
            except ValueError as exc:
                raise ValidationError(f"infrastructure.{name}: {exc}") from exc
        try:
            ipaddress.ip_network(self.ipv6_prefix, strict=False)
            ipaddress.ip_address(self.ipv6_gateway)
        except ValueError as exc:
            raise ValidationError(f"infrastructure.ipv6: {exc}") from exc
        for value in self.egress_allow:
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValidationError(f"infrastructure.egress_allow: {value!r}: {exc}") from exc


@dataclass
class DeviceConfig:
    adb_serial: str = ""
    mac: str = ""
    require_user_confirmation: bool = True

    def validate(self) -> None:
        if self.mac:
            parts = self.mac.split(":")
            if len(parts) != 6 or any(len(p) != 2 for p in parts):
                raise ValidationError(f"device.mac invalid: {self.mac!r}")


@dataclass
class FirewallConfig:
    architecture: str = "auto"
    package: str = ""

    def validate(self) -> None:
        if self.architecture not in {"auto", "vpnservice", "root", "private_dns", "api"}:
            raise ValidationError(f"firewall.architecture invalid: {self.architecture!r}")


@dataclass
class TestConfig:
    auto_select: bool = True
    include_categories: list[str] = field(default_factory=list)
    exclude_test_ids: list[str] = field(default_factory=list)
    observation_window_seconds: float = 6.0
    repeat_count: int = 1
    random_seed: int = 42
    # Cookie values are synthetic, but reports redact them unless this is explicitly on.
    reveal_cookie_values: bool = False
    # Certificate installation is a separate, documented opt-in experiment. It is off by
    # default and no test may install a CA without it.
    allow_certificate_install_opt_in: bool = False
    # Campaigns are multi-stage; dynamic assembly from discovered conditions is opt-in.
    allow_dynamic_campaigns: bool = True

    def validate(self) -> None:
        if self.observation_window_seconds <= 0:
            raise ValidationError("tests.observation_window_seconds must be > 0")
        if self.repeat_count < 1:
            raise ValidationError("tests.repeat_count must be >= 1")
        if not self.include_categories:
            self.include_categories = [
                "discovery",
                "dns",
                "dhcp",
                "arp",
                "ipv6",
                "tls",
                "http",
                "mobile",
                "wireless",
                "chain",
            ]


@dataclass
class AssessmentConfig:
    run_recovery_checks: bool = True
    verify_isolation: bool = True
    max_concurrent_scenarios: int = 1
    stop_on_critical: bool = False
    # Multi-stage campaigns run after the single-test pass. Campaigns reuse the same
    # orchestrator and preserve observations between stages.
    run_campaigns: bool = True
    campaign_ids: list[str] = field(default_factory=list)
    # Dynamically assembled campaigns use conditions discovered during the assessment.
    allow_dynamic_campaigns: bool = True

    def validate(self) -> None:
        if self.max_concurrent_scenarios < 1:
            raise ValidationError("assessment.max_concurrent_scenarios must be >= 1")


@dataclass
class LabConfig:
    lab: dict[str, Any] = field(default_factory=dict)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    infrastructure: InfrastructureConfig = field(default_factory=InfrastructureConfig)
    device: DeviceConfig = field(default_factory=DeviceConfig)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    tests: TestConfig = field(default_factory=TestConfig)
    assessment: AssessmentConfig = field(default_factory=AssessmentConfig)

    def validate(self) -> None:
        self.scope.validate()
        self.infrastructure.validate()
        self.device.validate()
        self.firewall.validate()
        self.tests.validate()
        self.assessment.validate()
        # Lab gateway must be inside the lab subnet.
        try:
            subnet = ipaddress.ip_network(self.infrastructure.ipv4_subnet, strict=False)
            gw = ipaddress.ip_address(self.infrastructure.ipv4_gateway)
            if gw not in subnet:
                raise ValidationError("infrastructure.ipv4_gateway is outside ipv4_subnet")
        except ValidationError:
            raise
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc


def default_config() -> LabConfig:
    cfg = LabConfig()
    cfg.tests.validate()  # populate default categories
    cfg.validate()
    return cfg
