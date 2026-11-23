"""Test specification metadata.

Every test module exposes a complete specification. Nothing is implicit: prerequisites,
observation strategy, evidence requirements, cleanup and known limitations are all
machine-readable so the planner can gate tests and the report can explain skips.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..core.capability import Capability
from ..core.results import ExecutionMode


class TestCategory(str, Enum):
    DISCOVERY = "discovery"
    DNS = "dns"
    DHCP = "dhcp"
    ARP = "arp"
    IPV6 = "ipv6"
    L2 = "l2"
    L3 = "l3"
    TLS = "tls"
    HTTP = "http"
    MOBILE = "mobile"
    WIRELESS = "wireless"
    CHAIN = "chain"
    INFRA = "infra"


@dataclass
class TestSpec:
    id: str
    name: str
    category: TestCategory
    description: str
    attack_techniques: list[str] = field(default_factory=list)
    required_capabilities: list[Capability] = field(default_factory=list)
    hardware_prerequisites: list[str] = field(default_factory=list)
    software_prerequisites: list[str] = field(default_factory=list)
    device_prerequisites: list[str] = field(default_factory=list)
    lab_prerequisites: list[str] = field(default_factory=list)
    setup_procedure: str = ""
    execution_procedure: str = ""
    expected_behavior: str = ""
    observation_strategy: str = ""
    evidence_requirements: list[str] = field(default_factory=list)
    cleanup_procedure: str = ""
    recovery_procedure: str = ""
    verdict_logic: str = ""
    known_limitations: list[str] = field(default_factory=list)
    execution_mode: ExecutionMode = ExecutionMode.REAL_NETWORK
    expect_block: bool = True
    require_firewall_confirmation: bool = True
    treat_timeout_as_block: bool = False
    estimated_duration_seconds: float = 10.0
    requires_user_confirmation: bool = False
    destructive: bool = False
    version: str = "1.0"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "attack_techniques": list(self.attack_techniques),
            "required_capabilities": [c.value for c in self.required_capabilities],
            "hardware_prerequisites": list(self.hardware_prerequisites),
            "software_prerequisites": list(self.software_prerequisites),
            "device_prerequisites": list(self.device_prerequisites),
            "lab_prerequisites": list(self.lab_prerequisites),
            "setup_procedure": self.setup_procedure,
            "execution_procedure": self.execution_procedure,
            "expected_behavior": self.expected_behavior,
            "observation_strategy": self.observation_strategy,
            "evidence_requirements": list(self.evidence_requirements),
            "cleanup_procedure": self.cleanup_procedure,
            "recovery_procedure": self.recovery_procedure,
            "verdict_logic": self.verdict_logic,
            "known_limitations": list(self.known_limitations),
            "execution_mode": self.execution_mode.value,
            "expect_block": self.expect_block,
            "require_firewall_confirmation": self.require_firewall_confirmation,
            "treat_timeout_as_block": self.treat_timeout_as_block,
            "estimated_duration_seconds": self.estimated_duration_seconds,
            "requires_user_confirmation": self.requires_user_confirmation,
            "destructive": self.destructive,
            "version": self.version,
        }
