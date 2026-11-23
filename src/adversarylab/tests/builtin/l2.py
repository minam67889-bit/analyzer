"""Layer-2 adversary scenarios."""

from __future__ import annotations

from ...core.capability import Capability
from ...core.events import EventCategory
from ...core.results import ExecutionMode, Observation
from ..spec import TestCategory, TestSpec
from .common import BuiltinModule, capture_events, firewall_events


class ArpSpoofGatewayTest(BuiltinModule):
    spec = TestSpec(
        id="ARP-SPOOF-GATEWAY",
        name="ARP spoofing of the default gateway",
        category=TestCategory.ARP,
        description="Poison the device ARP cache so the lab gateway MAC points at the adversary.",
        attack_techniques=["T1557.002"],
        required_capabilities=[Capability.PACKET_CAPTURE, Capability.IPV4],
        setup_procedure="Position the lab on-path or on the same L2 segment.",
        execution_procedure="Send unsolicited ARP replies mapping the gateway IP to the lab MAC.",
        expected_behavior="The firewall/device detects or contains the ARP manipulation.",
        observation_strategy="ARP parser + connection outcome + firewall telemetry.",
        evidence_requirements=["capture", "arp_events", "sink_hits"],
        cleanup_procedure="Restore correct ARP entries (revert_all).",
        recovery_procedure="Verify the device ARP cache returns to the legitimate gateway.",
        verdict_logic="PASS only with firewall-confirmed detection; INCONCLUSIVE if the attack is invisible.",
        known_limitations=["Requires on-path position or shared L2 segment."],
        execution_mode=ExecutionMode.REAL_NETWORK,
        expect_block=True,
        estimated_duration_seconds=15,
    )

    def execute(self) -> None:
        self.target = self.ctx.param("device_ip", "10.10.0.50")
        self.gateway = self.ctx.param("gateway", "10.10.0.1")
        self._run("start_sink", protocol="tcp", port=8445, name="arp-sink")
        self._run("arp_spoof", target_ip=self.target, spoof_ip=self.gateway, count=20)

    def collect(self):
        observations = super().collect()
        arp_events = [
            e for e in capture_events(self.ctx)
            if e.category is EventCategory.ARP and e.details.get("arp_op") == 2
        ]
        if arp_events:
            observations.append(Observation(
                "packet_capture", "detected", self.ctx.clock.now(),
                f"gratuitous ARP replies observed={len(arp_events)}",
                count=len(arp_events),
            ))
        blocked = [
            e for e in firewall_events(self.ctx)
            if "block" in e.summary.lower() or "detect" in e.summary.lower()
        ]
        for event in blocked:
            observations.append(Observation(
                "firewall", "firewall_block", event.timestamp, event.summary, **dict(event.details)
            ))
        if not arp_events and not blocked:
            observations.append(Observation(
                "packet_capture", "no_observations", self.ctx.clock.now(),
                "no ARP manipulation observed",
            ))
        return observations
