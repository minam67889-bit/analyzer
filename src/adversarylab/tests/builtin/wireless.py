"""Wireless (802.11) adversary scenarios.

All of these require a monitor-mode + injection-capable radio and Npcap raw 802.11. The
planner marks them ``UNSUPPORTED`` when the capability is absent; they are never reported
as verified from a simulation.
"""

from __future__ import annotations

from ...core.capability import Capability
from ...core.events import EventCategory
from ...core.results import ExecutionMode, Observation
from ..spec import TestCategory, TestSpec
from .common import BuiltinModule, bus_events


def _wireless_spec(test_id: str, name: str, description: str, **overrides) -> TestSpec:
    base = dict(
        id=test_id, name=name, category=TestCategory.WIRELESS, description=description,
        attack_techniques=["T1498", "T1557.004"],
        required_capabilities=[
            Capability.WIFI_MONITOR_MODE, Capability.WIFI_INJECTION,
            Capability.RAW_80211, Capability.PACKET_CAPTURE,
        ],
        hardware_prerequisites=[
            "monitor-mode + frame-injection Wi-Fi radio",
            "Npcap installed with raw 802.11 support",
        ],
        setup_procedure="Attach the injection radio to the lab channel; start raw capture.",
        execution_procedure="Inject the wireless condition and observe device behavior.",
        expected_behavior="The device/firewall detects or resists the wireless manipulation.",
        observation_strategy="Raw 802.11 capture + device telemetry.",
        evidence_requirements=["pcap", "management_frames", "device_telemetry"],
        cleanup_procedure="Stop injection; restore the legitimate AP.",
        recovery_procedure="Verify the device reconnects to the legitimate BSSID.",
        verdict_logic="PASS only with RF-level evidence; never from a protocol simulation.",
        known_limitations=[
            "Hardware/driver dependent; PMF and WPA3 may prevent management-frame injection.",
        ],
        execution_mode=ExecutionMode.REAL_NETWORK,
        expect_block=True,
        estimated_duration_seconds=15,
        requires_user_confirmation=True,
    )
    base.update(overrides)
    return TestSpec(**base)


class DeauthFloodTest(BuiltinModule):
    spec = _wireless_spec(
        "DEAUTH-FLOOD",
        "802.11 deauthentication flood",
        "Send forged deauthentication frames and observe whether PMF/device policy contains the impact.",
        attack_techniques=["T1498"],
    )

    def execute(self) -> None:
        self.client_mac = self.ctx.param("client_mac", "")
        self.ap_mac = self.ctx.param("ap_mac", "")
        self._run("deauth", client_mac=self.client_mac, ap_mac=self.ap_mac, count=10)

    def collect(self):
        observations = super().collect()
        frames = [
            e for e in bus_events(self.ctx, categories={EventCategory.PACKET})
            if "deauth" in e.summary.lower()
        ]
        observations.append(Observation(
            "packet_capture",
            "detected" if frames else "no_observations",
            self.ctx.clock.now(),
            f"deauth frames observed={len(frames)}", count=len(frames),
        ))
        return observations


class EvilTwinTest(BuiltinModule):
    spec = _wireless_spec(
        "EVIL-TWIN",
        "Evil twin access point",
        "Stand up a rogue AP with the same SSID and observe whether the device associates.",
        attack_techniques=["T1557.004"],
    )

    def execute(self) -> None:
        self.ssid = self.ctx.param("ssid", "AdversaryLab")
        self._run("start_evil_twin", ssid=self.ssid, bssid=self.ctx.param("bssid", ""))

    def collect(self):
        observations = super().collect()
        assoc = [
            e for e in bus_events(self.ctx, categories={EventCategory.PACKET})
            if "assoc" in e.summary.lower() or "auth" in e.summary.lower()
        ]
        observations.append(Observation(
            "packet_capture",
            "detected" if assoc else "no_observations",
            self.ctx.clock.now(),
            f"association events={len(assoc)}", count=len(assoc),
        ))
        return observations


class PmfDowngradeTest(BuiltinModule):
    spec = _wireless_spec(
        "PMF-DOWNGRADE",
        "Protected Management Frame downgrade",
        "Attempt to force an unprotected-management-frame association and observe PMF enforcement.",
        attack_techniques=["T1562"],
    )

    def execute(self) -> None:
        self.ssid = self.ctx.param("ssid", "AdversaryLab")
        self._run("pmf_downgrade", ssid=self.ssid)

    def collect(self):
        observations = super().collect()
        frames = [e for e in bus_events(self.ctx, categories={EventCategory.PACKET})]
        observations.append(Observation(
            "packet_capture",
            "detected" if frames else "no_observations",
            self.ctx.clock.now(),
            f"wireless events={len(frames)}", count=len(frames),
        ))
        return observations
