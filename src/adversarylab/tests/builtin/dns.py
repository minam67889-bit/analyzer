"""DNS manipulation scenarios."""

from __future__ import annotations

from ...core.capability import Capability
from ...core.events import EventCategory
from ...core.results import ExecutionMode, Observation
from ..spec import TestCategory, TestSpec
from .common import BuiltinModule, capture_events, firewall_events, sink_hits


def _spec(test_id: str, name: str, description: str, **overrides) -> TestSpec:
    base = dict(
        id=test_id,
        name=name,
        category=TestCategory.DNS,
        description=description,
        attack_techniques=["T1557"],
        required_capabilities=[Capability.PACKET_CAPTURE, Capability.IPV4],
        setup_procedure="Configure lab DNS and a lab sink; start capture.",
        execution_procedure="Apply the DNS manipulation and observe resolution + connection.",
        expected_behavior="The mobile firewall detects or blocks the manipulated resolution path.",
        observation_strategy="Capture DNS + TCP outcomes, lab DNS log, firewall telemetry.",
        evidence_requirements=["dns_log", "capture", "sink_hits"],
        cleanup_procedure="Restore DNS responder policy.",
        recovery_procedure="Revert DNS configuration; verify original resolver answers.",
        verdict_logic="PASS/PASS-equivalent only with firewall-confirmed block evidence; INCONCLUSIVE if only a network failure is seen.",
        known_limitations=["Encrypted DNS may hide query names; only transport metadata is used."],
        execution_mode=ExecutionMode.REAL_NETWORK,
        expect_block=True,
        estimated_duration_seconds=12,
    )
    base.update(overrides)
    return TestSpec(**base)


class DnsSpoofATest(BuiltinModule):
    spec = _spec(
        "DNS-SPOOF-A",
        "DNS A-record spoofing",
        "Answer a lab-owned name with a lab-controlled address and observe whether protected connections follow.",
    )

    def execute(self) -> None:
        self.qname = self.ctx.param("qname", "spoofed.lab.test")
        self.answer = self.ctx.param("answer", "10.10.0.250")
        self._run("start_sink", protocol="tcp", port=8443, name="dns-spoof-sink")
        self._run("dns_spoof", qname=self.qname, answer=self.answer, ttl=10)

    def collect(self):
        observations = super().collect()
        if sink_hits(self.ctx, "dns-spoof-sink"):
            observations.append(Observation("lab_server", "allowed", self.ctx.clock.now(),
                                            "traffic reached the spoofed destination",
                                            details={"target": self.answer}))
            return observations
        observations.extend(self._connection_evidence(self.answer))
        return observations

    def _connection_evidence(self, target: str) -> list[Observation]:
        out: list[Observation] = []
        for event in capture_events(self.ctx):
            if event.category is not EventCategory.CONNECTION:
                continue
            flags = event.details.get("tcp_flags") or []
            if event.dst_addr != target:
                continue
            if "RST" in flags:
                out.append(Observation("packet_capture", "blocked", event.timestamp,
                                       "RST observed", details={"dst": target, "flags": flags}))
            elif "SYN" in flags:
                out.append(Observation("packet_capture", "detected", event.timestamp,
                                       "SYN observed (attempt)",
                                       details={"dst": target, "flags": flags}))
        out.extend(
            Observation("firewall", "firewall_block", e.timestamp, e.summary,
                        details=dict(e.details))
            for e in firewall_events(self.ctx)
            if "block" in (e.details.get("action") or "").lower() or "blocked" in e.summary.lower()
        )
        if not out:
            out.append(Observation("packet_capture", "no_observations", self.ctx.clock.now(),
                                   "no connection outcome observed", details={"target": target}))
        return out


class DnsRebindPrivateTest(BuiltinModule):
    spec = _spec(
        "DNS-REBIND-PRIVATE",
        "DNS rebinding to a private address",
        "Resolve a public-looking name to a lab-private address after a short TTL, testing same-origin rebinding defenses.",
        attack_techniques=["T1557"],
        known_limitations=["Requires a client that honors the short TTL."],
    )

    def execute(self) -> None:
        self.qname = self.ctx.param("qname", "rebind.lab.test")
        self.public = self.ctx.param("public_ip", "203.0.113.10")
        self.private = self.ctx.param("private_ip", "10.10.0.251")
        self._run("start_sink", protocol="tcp", port=8444, name="rebind-sink")
        self._run("dns_rebind", qname=self.qname, public_ip=self.public, private_ip=self.private)

    def collect(self):
        observations = super().collect()
        if sink_hits(self.ctx, "rebind-sink"):
            observations.append(Observation("lab_server", "allowed", self.ctx.clock.now(),
                                            "rebound connection reached lab sink",
                                            details={"target": self.private}))
        else:
            observations.append(Observation("packet_capture", "no_observations",
                                            self.ctx.clock.now(),
                                            "no rebound connection observed",
                                            details={"target": self.private}))
        return observations


class DnsRebindCnameTest(BuiltinModule):
    spec = _spec(
        "DNS-REBIND-CNAME",
        "DNS rebinding via CNAME to localhost",
        "Answer with a CNAME that resolves to localhost, bypassing private-IP answer filters.",
        attack_techniques=["T1557"],
        known_limitations=["Effect depends on the client resolver's CNAME handling."],
    )

    def execute(self) -> None:
        self.qname = self.ctx.param("qname", "cname-rebind.lab.test")
        self._run("dns_cname", qname=self.qname, target="localhost.")

    def collect(self):
        observations = super().collect()
        dns_events = [e for e in capture_events(self.ctx) if e.category is EventCategory.DNS]
        observations.append(
            Observation("packet_capture",
                        "dns_answer_observed" if dns_events else "no_observations",
                        self.ctx.clock.now(),
                        f"DNS events={len(dns_events)}", count=len(dns_events))
        )
        return observations


class DnsLeakUnderlyingTest(BuiltinModule):
    spec = _spec(
        "DNS-LEAK-UNDERLYING",
        "DNS leak to the underlying network",
        "Detect DNS queries that bypass the firewall/VPN resolver and reach an underlying resolver.",
        attack_techniques=["T1557"],
        expect_block=True,
        known_limitations=["Requires visibility of the underlying resolver address."],
    )

    def execute(self) -> None:
        self.lab_resolvers = set(self.ctx.param("lab_resolvers", ["10.10.0.1"]))

    def collect(self):
        observations = super().collect()
        leaked = [
            e for e in capture_events(self.ctx)
            if e.category is EventCategory.DNS
            and e.dst_addr not in self.lab_resolvers
        ]
        if leaked:
            observations.append(Observation("packet_capture", "allowed", self.ctx.clock.now(),
                                            f"DNS leak to {sorted({e.dst_addr for e in leaked})}",
                                            details={"destinations": sorted({e.dst_addr for e in leaked})}))
        else:
            observations.append(Observation("packet_capture", "no_observations",
                                            self.ctx.clock.now(), "no plaintext DNS leak observed"))
        return observations


class DnsDotSteerTest(BuiltinModule):
    spec = _spec(
        "DNS-DOT-STEER",
        "DNS-over-TLS resolver steering",
        "Attempt to steer encrypted DNS to a non-lab resolver and observe resolver selection.",
        attack_techniques=["T1557", "T1572"],
        required_capabilities=[Capability.PACKET_CAPTURE, Capability.IPV6],
        known_limitations=["DoT payload is encrypted; only destination/port metadata is visible."],
    )

    def execute(self) -> None:
        self.lab_resolvers = set(self.ctx.param("lab_resolvers", ["10.10.0.1"]))

    def collect(self):
        observations = super().collect()
        dot = [
            e for e in capture_events(self.ctx)
            if e.dst_port == 853 or e.src_port == 853
        ]
        steered = [e for e in dot if e.dst_addr not in self.lab_resolvers]
        if steered:
            observations.append(Observation("packet_capture", "allowed", self.ctx.clock.now(),
                                            "DoT to non-lab resolver", destinations=sorted({e.dst_addr for e in steered})))
        elif dot:
            observations.append(Observation("packet_capture", "detected", self.ctx.clock.now(),
                                            "DoT only to lab resolver", destinations=sorted({e.dst_addr for e in dot})))
        else:
            observations.append(Observation("packet_capture", "no_observations",
                                            self.ctx.clock.now(), "no DoT traffic observed"))
        return observations
