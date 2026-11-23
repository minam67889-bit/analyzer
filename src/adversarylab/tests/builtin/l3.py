"""Layer-3 and IPv6 adversary scenarios."""

from __future__ import annotations

from ...core.capability import Capability
from ...core.events import EventCategory
from ...core.results import ExecutionMode, Observation
from ..spec import TestCategory, TestSpec
from .common import BuiltinModule, capture_events


class GatewayImpersonationTest(BuiltinModule):
    spec = TestSpec(
        id="GW-IMPERSONATION",
        name="Default gateway impersonation",
        category=TestCategory.L3,
        description="Introduce a second gateway and observe whether protected traffic follows it.",
        attack_techniques=["T1557", "T1030"],
        required_capabilities=[Capability.PACKET_CAPTURE, Capability.IPV4],
        setup_procedure="Add an alternate gateway on the lab subnet.",
        execution_procedure="Advertise/install the alternate gateway; observe the device route.",
        expected_behavior="The firewall prevents traffic from using the unexpected gateway.",
        observation_strategy="Route telemetry + capture of egress paths + sink hits.",
        evidence_requirements=["capture", "route_telemetry", "sink_hits"],
        cleanup_procedure="Remove the alternate gateway and restore routes.",
        recovery_procedure="Verify the original default route is restored.",
        verdict_logic="PASS with firewall-confirmed containment; FAIL if traffic follows the rogue gateway.",
        known_limitations=["Requires the device to accept the alternate gateway."],
        execution_mode=ExecutionMode.REAL_NETWORK,
        expect_block=True,
        estimated_duration_seconds=15,
    )

    def execute(self) -> None:
        self.fake_gateway = self.ctx.param("fake_gateway", "10.10.0.199")
        self._run("start_sink", protocol="tcp", port=8446, name="gw-sink")
        self._run("route", destination="0.0.0.0/0", gateway=self.fake_gateway)

    def collect(self):
        observations = super().collect()
        route_events = [
            e for e in capture_events(self.ctx)
            if e.category is EventCategory.ROUTE_STATE
        ]
        if route_events:
            observations.append(Observation(
                "packet_capture", "detected", self.ctx.clock.now(),
                "route change observed", routes=[e.summary for e in route_events],
            ))
        else:
            observations.append(Observation(
                "packet_capture", "no_observations", self.ctx.clock.now(),
                "no route change observed",
            ))
        return observations


class Ipv6BypassTest(BuiltinModule):
    spec = TestSpec(
        id="IPV6-BYPASS",
        name="IPv6 bypass of IPv4 firewall policy",
        category=TestCategory.IPV6,
        description="Observe whether traffic switches to IPv6 to bypass IPv4-only firewall rules.",
        attack_techniques=["T1065", "T1557"],
        required_capabilities=[Capability.PACKET_CAPTURE, Capability.IPV6],
        setup_procedure="Enable dual-stack lab services and capture.",
        execution_procedure="Advertise IPv6 and observe address selection and flows.",
        expected_behavior="IPv6 traffic is subject to the same policy as IPv4.",
        observation_strategy="IPv6 packet capture + destination inventory.",
        evidence_requirements=["capture", "ipv6_flows"],
        cleanup_procedure="Withdraw IPv6 routes/RA.",
        recovery_procedure="Verify IPv6 state returns to baseline.",
        verdict_logic="FAIL if protected IPv6 flows bypass policy; PASS with confirmed containment.",
        known_limitations=["Requires the device to prefer IPv6."],
        execution_mode=ExecutionMode.REAL_NETWORK,
        expect_block=True,
        estimated_duration_seconds=12,
    )

    def execute(self) -> None:
        self.lab_prefix = self.ctx.param("ipv6_prefix", "fd00:1234::/64")
        self._run("ra_inject", prefix=self.lab_prefix, gateway="fd00:1234::1")

    def collect(self):
        observations = super().collect()
        v6 = [e for e in capture_events(self.ctx) if ":" in (e.src_addr or "") or ":" in (e.dst_addr or "")]
        if v6:
            observations.append(Observation(
                "packet_capture", "detected", self.ctx.clock.now(),
                f"IPv6 flows observed={len(v6)}", count=len(v6),
            ))
        else:
            observations.append(Observation(
                "packet_capture", "no_observations", self.ctx.clock.now(),
                "no IPv6 flows observed",
            ))
        return observations


class RaInjectionTest(BuiltinModule):
    spec = TestSpec(
        id="ND-RA-INJECTION",
        name="IPv6 Router Advertisement injection",
        category=TestCategory.IPV6,
        description="Inject a rogue RA to install an attacker IPv6 default router.",
        attack_techniques=["T1557"],
        required_capabilities=[Capability.WIFI_INJECTION, Capability.IPV6, Capability.PACKET_CAPTURE],
        hardware_prerequisites=["monitor-mode + injection-capable radio"],
        setup_procedure="Attach the injection radio to the lab channel.",
        execution_procedure="Send RA messages with an attacker prefix and router lifetime.",
        expected_behavior="The device/firewall rejects or contains the rogue RA.",
        observation_strategy="802.11/ICMPv6 capture + device IPv6 route telemetry.",
        evidence_requirements=["capture", "ra_frames", "route_telemetry"],
        cleanup_procedure="Stop RA injection; withdraw the rogue prefix.",
        recovery_procedure="Verify the original IPv6 default route.",
        verdict_logic="PASS with confirmed containment; INCONCLUSIVE without RF capture.",
        known_limitations=["Requires monitor mode and injection support; hardware-dependent."],
        execution_mode=ExecutionMode.REAL_NETWORK,
        expect_block=True,
        estimated_duration_seconds=15,
    )

    def execute(self) -> None:
        self.prefix = self.ctx.param("prefix", "fd00:9999::/64")
        self._run("ra_inject", prefix=self.prefix, gateway="fd00:9999::1")

    def collect(self):
        observations = super().collect()
        ra = [
            e for e in capture_events(self.ctx)
            if e.category is EventCategory.IPV6_NEIGHBOR and e.details.get("icmpv6_type") == 134
        ]
        observations.append(Observation(
            "packet_capture",
            "detected" if ra else "no_observations",
            self.ctx.clock.now(),
            f"RA frames observed={len(ra)}", count=len(ra),
        ))
        return observations
