"""Android firewall-specific scenarios.

These tests rely on ADB telemetry and the device's own state. They are hardware-dependent
and are marked ``UNSUPPORTED`` by the planner when ADB/device telemetry is unavailable.
"""

from __future__ import annotations

from ...core.capability import Capability
from ...core.events import EventCategory, EventSource
from ...core.results import ExecutionMode, Observation
from ..spec import TestCategory, TestSpec
from .common import BuiltinModule, bus_events


def _spec(test_id: str, name: str, description: str, expect_block: bool, **overrides) -> TestSpec:
    base = dict(
        id=test_id, name=name, category=TestCategory.MOBILE, description=description,
        attack_techniques=["T1557"],
        required_capabilities=[Capability.ADB, Capability.PACKET_CAPTURE],
        device_prerequisites=["authorized Android device with USB debugging"],
        setup_procedure="Validate the device and record baseline VPN/route state.",
        execution_procedure="Exercise the firewall state and observe behavior.",
        expected_behavior="The firewall maintains policy across the tested state.",
        observation_strategy="ADB dumpsys/ip/settings + capture + lab logs.",
        evidence_requirements=["android_telemetry", "capture"],
        cleanup_procedure="Restore the firewall/VPN state.",
        recovery_procedure="Confirm baseline state and connectivity.",
        verdict_logic="See per-test notes; INCONCLUSIVE when telemetry is insufficient.",
        known_limitations=["Device-side telemetry granularity depends on Android version and OEM."],
        execution_mode=ExecutionMode.REAL_NETWORK,
        expect_block=expect_block,
        estimated_duration_seconds=15,
    )
    base.update(overrides)
    return TestSpec(**base)


class VpnContinuityTest(BuiltinModule):
    spec = _spec(
        "VPN-CONTINUITY",
        "VPN tunnel continuity",
        "Observe whether the firewall keeps the tunnel up and routes/DNS consistent.",
        expect_block=False,
        verdict_logic="PASS if the VPN interface and routes are present; FAIL if the tunnel dropped.",
    )

    def execute(self) -> None:
        self._run("device_snapshot")

    def collect(self):
        observations = super().collect()
        events = bus_events(self.ctx, categories={EventCategory.VPN_STATE})
        if events:
            observations.append(Observation(
                "android_device",
                "allowed" if any("tun" in (e.details.get("interface") or "") for e in events) else "detected",
                self.ctx.clock.now(),
                "VPN state observed", interfaces=[e.details.get("interface") for e in events],
            ))
        else:
            observations.append(Observation(
                "android_device", "no_observations", self.ctx.clock.now(),
                "no VPN telemetry observed",
            ))
        return observations


class VpnFailOpenTest(BuiltinModule):
    spec = _spec(
        "VPN-FAILOPEN",
        "Fail-open behavior when the firewall stops",
        "Stop the firewall/VPN and observe whether traffic flows outside the tunnel.",
        expect_block=True,
        verdict_logic="PASS if traffic is blocked with the firewall down; FAIL if it flows (fail-open).",
        device_prerequisites=["ability to stop the firewall app via ADB (opt-in)"],
        requires_user_confirmation=True,
    )

    def execute(self) -> None:
        self._run("stop_vpn")

    def collect(self):
        observations = super().collect()
        leaked = [
            e for e in bus_events(self.ctx, categories={EventCategory.CONNECTION},
                                  sources={EventSource.PACKET_CAPTURE})
            if e.dst_addr not in set(self.ctx.param("lab_ranges", ["10.10.0.0/16"]))
        ]
        if leaked:
            observations.append(Observation(
                "packet_capture", "allowed", self.ctx.clock.now(),
                "traffic observed while the firewall is down",
                count=len(leaked),
            ))
        else:
            observations.append(Observation(
                "packet_capture", "no_observations", self.ctx.clock.now(),
                "no traffic observed while the firewall is down",
            ))
        return observations


class NetworkTransitionTest(BuiltinModule):
    spec = _spec(
        "NET-TRANSITION",
        "Wi-Fi to cellular network transition",
        "Observe firewall behavior when the device switches transports.",
        expect_block=False,
        verdict_logic="PASS if the tunnel/policy survives the transition; INCONCLUSIVE without telemetry.",
    )

    def execute(self) -> None:
        self._run("network_switch", from_transport="wifi", to_transport="cellular")

    def collect(self):
        observations = super().collect()
        events = bus_events(self.ctx, categories={EventCategory.VPN_STATE, EventCategory.ROUTE_STATE})
        observations.append(Observation(
            "android_device",
            "allowed" if events else "no_observations",
            self.ctx.clock.now(),
            f"transition telemetry events={len(events)}", count=len(events),
        ))
        return observations


class PerAppPolicyTest(BuiltinModule):
    spec = _spec(
        "PER-APP-POLICY",
        "Per-application policy enforcement",
        "Verify that a disallowed application cannot reach the network while allowed apps can.",
        expect_block=True,
        verdict_logic="PASS if the disallowed app's traffic is blocked with firewall evidence; FAIL if it flows.",
        known_limitations=["Requires per-UID telemetry or distinguishable traffic."],
    )

    def execute(self) -> None:
        self._run("start_sink", protocol="tcp", port=8447, name="per-app-sink")

    def collect(self):
        observations = super().collect()
        observations.append(Observation(
            "android_device", "no_observations", self.ctx.clock.now(),
            "per-app telemetry not available in this run",
        ))
        return observations
