"""TLS / certificate validation scenarios."""

from __future__ import annotations

from ...core.capability import Capability
from ...core.events import EventCategory, EventSource
from ...core.results import ExecutionMode, Observation
from ..spec import TestCategory, TestSpec
from .common import BuiltinModule, bus_events


def _spec(test_id: str, name: str, description: str, **overrides) -> TestSpec:
    base = dict(
        id=test_id, name=name, category=TestCategory.TLS, description=description,
        attack_techniques=["T1557"],
        required_capabilities=[Capability.PACKET_CAPTURE, Capability.LAB_CA],
        setup_prerequisites=None,
        hardware_prerequisites=[],
        software_prerequisites=["cryptography (for lab CA)"],
        lab_prerequisites=["lab TLS endpoint"],
        setup_procedure="Generate the required certificate profile with the lab CA.",
        execution_procedure="Present the certificate and observe handshake outcome.",
        expected_behavior="The client/firewall rejects the misconfigured certificate.",
        observation_strategy="Lab TLS handshake log + capture of TLS records.",
        evidence_requirements=["tls_handshake_log", "capture"],
        cleanup_procedure="Stop the lab TLS endpoint.",
        recovery_procedure="Confirm the lab CA state is unchanged.",
        verdict_logic="PASS/PASS-equivalent when a handshake failure is observed; FAIL if the bad certificate is accepted.",
        known_limitations=["Application-level trust decisions may not be visible to the firewall."],
        execution_mode=ExecutionMode.REAL_NETWORK,
        expect_block=True,
        estimated_duration_seconds=12,
    )
    base.pop("setup_prerequisites", None)
    base.update(overrides)
    return TestSpec(**base)


def _handshake_observations(ctx) -> list[Observation]:
    events = [
        e for e in bus_events(ctx, categories={EventCategory.TLS}, sources={EventSource.LAB_SERVER})
    ]
    out: list[Observation] = []
    for event in events:
        success = bool(event.details.get("success"))
        out.append(Observation(
            "lab_server",
            "allowed" if success else "blocked",
            event.timestamp,
            event.summary,
            details={
                "sni": event.details.get("sni"),
                "version": event.details.get("version"),
                "error": event.details.get("error"),
            },
        ))
    return out


class TlsWrongCertTest(BuiltinModule):
    spec = _spec(
        "TLS-WRONG-CERT",
        "HTTPS with an untrusted self-signed certificate",
        "Present a self-signed certificate and verify the client rejects it.",
    )

    def execute(self) -> None:
        self.hostname = self.ctx.param("hostname", "untrusted.lab.test")
        self.port = int(self.ctx.param("port", 8443))
        self._run("start_tls", hostname=self.hostname, port=self.port, cert_mode="self_signed")

    def collect(self):
        observations = super().collect()
        handshakes = _handshake_observations(self.ctx)
        observations.extend(handshakes)
        if not handshakes:
            observations.append(Observation("lab_server", "no_observations", self.ctx.clock.now(),
                                            "no TLS handshake observed"))
        return observations


class TlsWrongHostnameTest(BuiltinModule):
    spec = _spec(
        "TLS-WRONG-HOSTNAME",
        "HTTPS certificate with the wrong hostname",
        "Present a lab-CA-signed certificate whose SAN does not match the requested hostname.",
    )

    def execute(self) -> None:
        self.hostname = self.ctx.param("hostname", "wrong.lab.test")
        self.port = int(self.ctx.param("port", 8444))
        self._run("start_tls", hostname=self.hostname, port=self.port, cert_mode="wrong_hostname")

    def collect(self):
        observations = super().collect()
        observations.extend(_handshake_observations(self.ctx))
        return observations


class TlsDowngradeTest(BuiltinModule):
    spec = _spec(
        "TLS-DOWNGRADE",
        "TLS protocol downgrade",
        "Offer only legacy TLS versions and verify the client refuses to downgrade.",
        known_limitations=["Requires the lab TLS endpoint to allow legacy minimum versions."],
    )

    def execute(self) -> None:
        self.hostname = self.ctx.param("hostname", "downgrade.lab.test")
        self.port = int(self.ctx.param("port", 8445))
        self._run("start_tls", hostname=self.hostname, port=self.port,
                  cert_mode="lab_ca", minimum_version="TLSv1")

    def collect(self):
        observations = super().collect()
        observations.extend(_handshake_observations(self.ctx))
        return observations


class TlsPinningTest(BuiltinModule):
    spec = _spec(
        "TLS-PINNING",
        "Certificate pinning behavior",
        "Present a lab-CA certificate for a pinned hostname and verify pinning rejection.",
        attack_techniques=["T1557", "MASVS-NETWORK-2"],
        known_limitations=["Pinning is application-specific; only observable if the target app implements it."],
    )

    def execute(self) -> None:
        self.hostname = self.ctx.param("hostname", "pinned.lab.test")
        self.port = int(self.ctx.param("port", 8446))
        self._run("start_tls", hostname=self.hostname, port=self.port, cert_mode="lab_ca")

    def collect(self):
        observations = super().collect()
        observations.extend(_handshake_observations(self.ctx))
        return observations
