"""Application-layer lab scenarios (HTTP, captive portal, WebSocket, QUIC)."""

from __future__ import annotations

from ...core.capability import Capability
from ...core.events import EventCategory, EventSource
from ...core.results import ExecutionMode, Observation
from ..spec import TestCategory, TestSpec
from .common import BuiltinModule, bus_events


def _lab_events(ctx, category: EventCategory) -> list:
    return bus_events(ctx, categories={category}, sources={EventSource.LAB_SERVER})


class HttpCleartextTest(BuiltinModule):
    spec = TestSpec(
        id="HTTP-CLEARTEXT",
        name="Plaintext HTTP to a lab endpoint",
        category=TestCategory.HTTP,
        description="Observe whether the firewall permits plaintext HTTP to a lab endpoint.",
        attack_techniques=["T1040"],
        required_capabilities=[Capability.PACKET_CAPTURE, Capability.IPV4],
        setup_procedure="Start a lab HTTP endpoint with a route for the test host.",
        execution_procedure="Serve the endpoint and observe the device request.",
        expected_behavior="Baseline HTTP is permitted and observable; cleartext is flagged.",
        observation_strategy="Lab HTTP log + capture HTTP metadata parser.",
        evidence_requirements=["http_log", "capture"],
        cleanup_procedure="Stop the HTTP endpoint.",
        recovery_procedure="No configuration change.",
        verdict_logic="PASS if the lab endpoint is reached (baseline); FAIL if unexpectedly blocked.",
        known_limitations=["This is a baseline/observation test, not an attack resistance proof."],
        execution_mode=ExecutionMode.REAL_NETWORK,
        expect_block=False,
        estimated_duration_seconds=10,
    )

    def execute(self) -> None:
        self.host = self.ctx.param("host", "plain.lab.test")
        self.port = int(self.ctx.param("port", 8080))
        self._run("start_http", host=self.host, path="/", body="<html>lab</html>", port=self.port)

    def collect(self):
        observations = super().collect()
        events = _lab_events(self.ctx, EventCategory.HTTP)
        observations.append(Observation(
            "lab_server", "sink_hit" if events else "no_observations", self.ctx.clock.now(),
            f"lab HTTP events={len(events)}", count=len(events),
        ))
        return observations


class CaptivePortalCloneTest(BuiltinModule):
    spec = TestSpec(
        id="CAPTIVE-PORTAL-CLONE",
        name="Captive portal clone",
        category=TestCategory.HTTP,
        description="Serve a captive portal clone and observe whether the device/firewall contains it.",
        attack_techniques=["T1185", "T1557.004"],
        required_capabilities=[Capability.PACKET_CAPTURE, Capability.IPV4],
        setup_procedure="Configure a portal route and start the lab HTTP endpoint.",
        execution_procedure="Serve the portal; observe probe requests (captive.apple.com style) and submissions.",
        expected_behavior="The firewall flags or blocks the captive portal interception.",
        observation_strategy="Lab HTTP log + capture of portal probe requests.",
        evidence_requirements=["http_log", "capture"],
        cleanup_procedure="Stop the HTTP endpoint.",
        recovery_procedure="No configuration change.",
        verdict_logic="PASS if the portal is contained; FAIL if a portal interception is not detected.",
        known_limitations=["Portal probes may be OS-initiated; distinguish OS from firewall behavior."],
        execution_mode=ExecutionMode.REAL_NETWORK,
        expect_block=True,
        estimated_duration_seconds=12,
    )

    def execute(self) -> None:
        self.host = self.ctx.param("host", "captive.lab.test")
        self.port = int(self.ctx.param("port", 8081))
        self._run("start_http", host=self.host, path="/",
                  body="<html><form action='/login'><input name='password'/></form></html>",
                  port=self.port)

    def collect(self):
        observations = super().collect()
        events = _lab_events(self.ctx, EventCategory.HTTP)
        observations.append(Observation(
            "lab_server",
            "detected" if events else "no_observations",
            self.ctx.clock.now(),
            f"portal events={len(events)}", count=len(events),
        ))
        return observations


class WebSocketEndpointTest(BuiltinModule):
    spec = TestSpec(
        id="WS-ENDPOINT",
        name="WebSocket lab endpoint",
        category=TestCategory.HTTP,
        description="Verify WebSocket upgrade and framing to a lab endpoint.",
        attack_techniques=["T1102"],
        required_capabilities=[Capability.PACKET_CAPTURE, Capability.IPV4],
        setup_procedure="Start the lab HTTP endpoint with WebSocket support.",
        execution_procedure="Perform an upgrade and exchange frames.",
        expected_behavior="Baseline WebSocket connectivity is established and observable.",
        observation_strategy="Lab HTTP/WebSocket log.",
        evidence_requirements=["http_log"],
        cleanup_procedure="Stop the HTTP endpoint.",
        recovery_procedure="No configuration change.",
        verdict_logic="PASS if the WebSocket upgrade is observed.",
        known_limitations=[],
        execution_mode=ExecutionMode.REAL_NETWORK,
        expect_block=False,
        estimated_duration_seconds=10,
    )

    def execute(self) -> None:
        self.host = self.ctx.param("host", "ws.lab.test")
        self.port = int(self.ctx.param("port", 8082))
        self._run("start_http", host=self.host, path="/ws", body="", port=self.port)

    def collect(self):
        observations = super().collect()
        events = _lab_events(self.ctx, EventCategory.HTTP)
        observations.append(Observation(
            "lab_server", "sink_hit" if events else "no_observations", self.ctx.clock.now(),
            f"WebSocket-related events={len(events)}", count=len(events),
        ))
        return observations


class QuicH3Test(BuiltinModule):
    spec = TestSpec(
        id="QUIC-H3",
        name="QUIC / HTTP-3 observation",
        category=TestCategory.HTTP,
        description="Observe QUIC/HTTP-3 behavior and confirm payload opacity.",
        attack_techniques=["T1102"],
        required_capabilities=[Capability.PACKET_CAPTURE, Capability.IPV4],
        setup_procedure="Start capture with a QUIC-capable lab endpoint.",
        execution_procedure="Observe QUIC Initial packets and metadata.",
        expected_behavior="QUIC metadata (version, CID, packet type) is observable; payload remains protected.",
        observation_strategy="QUIC parser; assert SNI is not inferred from protected payload.",
        evidence_requirements=["capture", "quic_metadata"],
        cleanup_procedure="Stop the QUIC endpoint.",
        recovery_procedure="No configuration change.",
        verdict_logic="PASS if QUIC metadata is observed without claiming payload visibility.",
        known_limitations=["QUIC Initial payload is protected; SNI is not recoverable."],
        execution_mode=ExecutionMode.REAL_NETWORK,
        expect_block=False,
        estimated_duration_seconds=10,
    )

    def execute(self) -> None:
        self.ctx.logger.info("QUIC observation window")

    def collect(self):
        observations = super().collect()
        quic = [e for e in bus_events(self.ctx, categories={EventCategory.QUIC})]
        observations.append(Observation(
            "packet_capture", "allowed" if quic else "no_observations", self.ctx.clock.now(),
            f"QUIC events={len(quic)}", count=len(quic),
        ))
        return observations
