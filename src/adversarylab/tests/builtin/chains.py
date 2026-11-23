"""Multi-stage attack chains."""

from __future__ import annotations

from ...core.capability import Capability
from ...core.results import ExecutionMode, Observation
from ..spec import TestCategory, TestSpec
from .common import BuiltinModule, capture_events


class MultiStageAitmChainTest(BuiltinModule):
    spec = TestSpec(
        id="MULTI-STAGE-AITM",
        name="Multi-stage adversary-in-the-middle chain",
        category=TestCategory.CHAIN,
        description=(
            "Chain: introduce an unexpected DNS configuration, observe resolution, then "
            "introduce a gateway condition and observe whether protected traffic follows."
        ),
        attack_techniques=["T1557", "T1557.002", "T1557.003"],
        required_capabilities=[Capability.PACKET_CAPTURE, Capability.IPV4],
        setup_procedure="Start capture, lab DNS, lab sink, and lab gateway controls.",
        execution_procedure=(
            "1) DNS spoof a lab name to a lab sink. 2) Observe resolution and connection. "
            "3) Inject a gateway condition. 4) Observe egress path. 5) Revert and verify recovery."
        ),
        expected_behavior="The firewall detects or contains at least one stage; recovery restores the original path.",
        observation_strategy="Unified event timeline across DNS, ARP, routing and connection events.",
        evidence_requirements=["capture", "dns_log", "arp_events", "route_telemetry"],
        cleanup_procedure="Revert all actions in reverse order.",
        recovery_procedure="Verify original DNS, gateway and routes.",
        verdict_logic="FAIL if all stages succeed; PASS/PASS-equivalent if the firewall confirms a block; otherwise INCONCLUSIVE.",
        known_limitations=["Chain outcomes are correlated, not assumed from individual stages."],
        execution_mode=ExecutionMode.REAL_NETWORK,
        expect_block=True,
        estimated_duration_seconds=30,
    )

    def execute(self) -> None:
        self.qname = self.ctx.param("qname", "chain.lab.test")
        self.answer = self.ctx.param("answer", "10.10.0.252")
        self.gateway = self.ctx.param("gateway", "10.10.0.199")
        self._run("start_sink", protocol="tcp", port=8448, name="chain-sink")
        self._run("dns_spoof", qname=self.qname, answer=self.answer, ttl=10)
        self._run("arp_spoof", target_ip=self.ctx.param("device_ip", "10.10.0.50"),
                  spoof_ip=self.gateway, count=20)

    def collect(self):
        observations = super().collect()
        categories = {}
        for event in capture_events(self.ctx):
            categories[event.category.value] = categories.get(event.category.value, 0) + 1
        observations.append(Observation(
            "packet_capture",
            "detected" if categories else "no_observations",
            self.ctx.clock.now(),
            f"chain event categories={sorted(categories)}",
            details={"categories": categories},
        ))
        return observations
