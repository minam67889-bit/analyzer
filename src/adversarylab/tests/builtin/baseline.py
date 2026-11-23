"""Laboratory baseline and passive discovery tests."""

from __future__ import annotations

from ...core.capability import Capability
from ...core.results import ExecutionMode, Observation
from ..spec import TestCategory, TestSpec
from .common import BuiltinModule, sink_hits


class LabBaselineTest(BuiltinModule):
    spec = TestSpec(
        id="LAB-BASELINE",
        name="Laboratory baseline reachability",
        category=TestCategory.INFRA,
        description="Verify the laboratory services are reachable from the authorized device.",
        attack_techniques=[],
        required_capabilities=[Capability.PACKET_CAPTURE, Capability.IPV4],
        setup_procedure="Start lab HTTP/TLS sinks; confirm capture is running.",
        execution_procedure="Observe device connections to lab sinks.",
        expected_behavior="Baseline lab traffic is permitted and observed.",
        observation_strategy="Capture + lab server logs + sink hit counters.",
        evidence_requirements=["capture", "sink_hits"],
        cleanup_procedure="Stop sinks.",
        recovery_procedure="Restore original network configuration.",
        verdict_logic="PASS if sink hit or allowed connection observed; INCONCLUSIVE otherwise.",
        known_limitations=["Requires the device to generate baseline traffic."],
        execution_mode=ExecutionMode.REAL_NETWORK,
        expect_block=False,
        estimated_duration_seconds=10,
    )

    def execute(self) -> None:
        self._run("start_sink", protocol="tcp", port=8080, name="baseline-http")
        self._run("start_sink", protocol="udp", port=5353, name="baseline-udp")

    def collect(self):
        observations = super().collect()
        hits = sink_hits(self.ctx, "baseline-http") + sink_hits(self.ctx, "baseline-udp")
        observations.append(
            Observation(
                source="lab_server",
                kind="sink_hit" if hits else "sink_no_hit",
                timestamp=self.ctx.clock.now(),
                summary=f"baseline sink hits={hits}",
                details={"hits": hits},
            )
        )
        return observations


class PassiveDnsDiscoveryTest(BuiltinModule):
    spec = TestSpec(
        id="DISC-DNS-PASSIVE",
        name="Passive DNS destination discovery",
        category=TestCategory.DISCOVERY,
        description="Build the destination inventory from observed DNS traffic without active probing.",
        attack_techniques=["T1040"],
        required_capabilities=[Capability.PACKET_CAPTURE],
        setup_procedure="Start passive capture before device interaction.",
        execution_procedure="Collect DNS queries/answers for the observation window.",
        expected_behavior="Destinations are inventoried and classified against the lab boundary.",
        observation_strategy="Packet capture DNS parser + inventory engine.",
        evidence_requirements=["capture", "inventory_export"],
        cleanup_procedure="Stop capture.",
        recovery_procedure="No configuration change.",
        verdict_logic="PASS if at least one destination is inventoried; INCONCLUSIVE if none observed.",
        known_limitations=["Encrypted DNS (DoH/DoT) may hide query names."],
        execution_mode=ExecutionMode.PASSIVE_OBSERVATION,
        expect_block=False,
        estimated_duration_seconds=20,
    )

    def execute(self) -> None:
        # Passive: no adversarial action. The orchestrator's capture feeds the inventory.
        self.ctx.logger.info("passive DNS discovery window started")

    def collect(self):
        observations = super().collect()
        dns_events = [e for e in observations if e.kind == "dns"]
        if dns_events:
            observations.append(
                Observation(
                    source="packet_capture",
                    kind="allowed",
                    timestamp=self.ctx.clock.now(),
                    summary=f"observed {len(dns_events)} DNS events",
                    details={"dns_events": len(dns_events)},
                )
            )
        else:
            observations.append(
                Observation(
                    source="packet_capture",
                    kind="no_observations",
                    timestamp=self.ctx.clock.now(),
                    summary="no DNS events observed",
                )
            )
        return observations
