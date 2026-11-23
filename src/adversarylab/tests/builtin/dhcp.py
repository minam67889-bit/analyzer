"""DHCP manipulation scenarios."""

from __future__ import annotations

from ...core.capability import Capability
from ...core.events import EventCategory, EventSource
from ...core.results import ExecutionMode, Observation
from ..spec import TestCategory, TestSpec
from .common import BuiltinModule, bus_events, capture_events


def _spec(test_id: str, name: str, description: str, **overrides) -> TestSpec:
    base = dict(
        id=test_id, name=name, category=TestCategory.DHCP, description=description,
        attack_techniques=["T1557.003"],
        required_capabilities=[Capability.PACKET_CAPTURE, Capability.IPV4],
        setup_procedure="Start lab DHCP with rogue configuration; start capture.",
        execution_procedure="Offer/ack a rogue router and DNS configuration.",
        expected_behavior="The firewall/device rejects or contains the rogue configuration.",
        observation_strategy="DHCP parser + device route/DNS telemetry.",
        evidence_requirements=["dhcp_log", "capture", "device_telemetry"],
        cleanup_procedure="Restore lab DHCP configuration.",
        recovery_procedure="Confirm the device reverts to the lab gateway/DNS.",
        verdict_logic="PASS only with firewall-confirmed rejection; INCONCLUSIVE otherwise.",
        known_limitations=["Requires the device to (re)request a lease."],
        execution_mode=ExecutionMode.REAL_NETWORK,
        expect_block=True,
        estimated_duration_seconds=12,
    )
    base.update(overrides)
    return TestSpec(**base)


class DhcpRogueGatewayTest(BuiltinModule):
    spec = _spec(
        "DHCP-ROGUE-GATEWAY",
        "Rogue DHCP gateway/DNS injection",
        "Inject an attacker-controlled default gateway and DNS server via DHCP.",
    )

    def execute(self) -> None:
        self.rogue_router = self.ctx.param("router", "10.10.0.199")
        self.rogue_dns = list(self.ctx.param("dns_servers", ["10.10.0.199"]))
        self._run("dhcp_rogue", router=self.rogue_router, dns_servers=self.rogue_dns)

    def collect(self):
        observations = super().collect()
        dhcp_events = [
            e for e in capture_events(self.ctx)
            if e.category is EventCategory.DHCP and e.details.get("msg_type_name") in {"OFFER", "ACK"}
        ]
        lab_events = [
            e for e in bus_events(self.ctx, sources={EventSource.LAB_SERVER})
            if e.category is EventCategory.DHCP
        ]
        if dhcp_events or lab_events:
            observations.append(Observation(
                "packet_capture", "detected", self.ctx.clock.now(),
                "rogue DHCP exchange observed",
                details={"rogue_router": self.rogue_router, "rogue_dns": self.rogue_dns},
            ))
        else:
            observations.append(Observation(
                "packet_capture", "no_observations", self.ctx.clock.now(),
                "no DHCP exchange observed",
            ))
        return observations


class DhcpOptionManipTest(BuiltinModule):
    spec = _spec(
        "DHCP-OPTION-MANIP",
        "DHCP option manipulation",
        "Change only DNS/router options while keeping the lab server identity, testing option validation.",
        known_limitations=["Requires the device to honor option changes mid-lease."],
    )

    def execute(self) -> None:
        self._run("dhcp_rogue", router="10.10.0.1", dns_servers=["10.10.0.199"])

    def collect(self):
        observations = super().collect()
        events = [
            e for e in capture_events(self.ctx)
            if e.category is EventCategory.DHCP
        ]
        observations.append(Observation(
            "packet_capture",
            "detected" if events else "no_observations",
            self.ctx.clock.now(),
            f"DHCP option exchange events={len(events)}",
            count=len(events),
        ))
        return observations
