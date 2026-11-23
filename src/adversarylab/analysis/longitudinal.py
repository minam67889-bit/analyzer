"""Longitudinal, session-aware traffic analysis.

Instead of judging each packet or connection on its own, the analyzer keeps every
observation for the whole assessment and correlates them: DNS answers to destinations,
destinations to connections, connections to TLS handshakes and HTTP exchanges, and all of
those to tests, scenarios and firewall decisions.

Outputs are explicitly confidence-labelled. Individually low-information observations are
combined only to describe *patterns* (recurrence, sequencing, persistence); the analyzer
never asserts that a specific authenticated user or session was identified unless a
plaintext identifier actually supports it.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from ..core.events import EventCategory, NetworkEvent
from ..logging_config import get_logger

logger = get_logger(__name__)

_CONFIDENCE_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


@dataclass
class Finding:
    kind: str
    summary: str
    confidence: str
    evidence_refs: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    caveat: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "summary": self.summary,
            "confidence": self.confidence,
            "evidence_refs": list(self.evidence_refs),
            "details": dict(self.details),
            "caveat": self.caveat,
        }


class SessionCorrelator:
    """Groups related events into flows and site sessions."""

    def __init__(self) -> None:
        self.flows: dict[str, dict[str, Any]] = {}
        self.dns_name_to_ips: dict[str, set[str]] = defaultdict(set)
        self.dns_ip_to_names: dict[str, set[str]] = defaultdict(set)
        self.domain_events: dict[str, list[NetworkEvent]] = defaultdict(list)
        self.cookie_observations: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.tls_by_flow: dict[str, dict[str, Any]] = {}
        self.http_by_flow: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.firewall_events: list[NetworkEvent] = []
        self.interruptions: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    def add(self, event: NetworkEvent) -> None:
        if event.category is EventCategory.DNS:
            self._add_dns(event)
        elif event.category is EventCategory.TLS:
            self._add_tls(event)
        elif event.category is EventCategory.HTTP:
            self._add_http(event)
        elif event.category is EventCategory.CONNECTION:
            self._add_connection(event)
        elif event.category is EventCategory.FIREWALL:
            self.firewall_events.append(event)
        elif event.category in {EventCategory.PACKET, EventCategory.ARP}:
            self._maybe_interruption(event)

    def _add_dns(self, event: NetworkEvent) -> None:
        details = dict(event.details or {})
        qname = str(details.get("qname") or "").rstrip(".").lower()
        if not qname:
            return
        self.domain_events[qname].append(event)
        for answer in details.get("answers") or []:
            address = answer.get("address") if isinstance(answer, dict) else None
            if address:
                self.dns_name_to_ips[qname].add(str(address))
                self.dns_ip_to_names[str(address)].add(qname)

    def _add_tls(self, event: NetworkEvent) -> None:
        details = dict(event.details or {})
        sni = details.get("sni")
        if not sni:
            return
        domain = str(sni).lower().rstrip(".")
        self.domain_events[domain].append(event)
        flow = _flow_key(event)
        self.tls_by_flow[flow] = {
            "sni": domain,
            "version": details.get("version"),
            "cipher": details.get("cipher"),
            "timestamp": event.timestamp.isoformat(),
            "dst_addr": event.dst_addr,
            "dst_port": event.dst_port,
        }

    def _add_http(self, event: NetworkEvent) -> None:
        details = dict(event.details or {})
        headers = {str(k).lower(): v for k, v in (details.get("headers") or {}).items()}
        host = (details.get("host") or headers.get("host") or "").split(":")[0].lower()
        if host:
            self.domain_events[host].append(event)
        cookie_header = headers.get("cookie")
        if cookie_header:
            self.cookie_observations[host or "unknown"].append({
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "cookie_header_present": True,
                "names": [name for name, _ in _parse_cookie_pairs(cookie_header)],
                "value_observable": True,
            })
        flow = _flow_key(event)
        self.http_by_flow[flow].append({
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "direction": details.get("direction") or ("request" if "cookie" in headers else "response"),
            "host": host,
            "target": details.get("target"),
            "status": details.get("status"),
            "location": details.get("location") or headers.get("location"),
        })

    def _add_connection(self, event: NetworkEvent) -> None:
        key = _flow_key(event)
        flow = self.flows.setdefault(key, {
            "key": key,
            "src_addr": event.src_addr,
            "dst_addr": event.dst_addr,
            "dst_port": event.dst_port,
            "protocol": event.protocol,
            "first_seen": event.timestamp.isoformat(),
            "last_seen": event.timestamp.isoformat(),
            "events": 0,
            "test_ids": set(),
            "scenario_ids": set(),
        })
        flow["last_seen"] = event.timestamp.isoformat()
        flow["events"] += 1
        if event.test_id:
            flow["test_ids"].add(event.test_id)
        if event.scenario_id:
            flow["scenario_ids"].add(event.scenario_id)

    def _maybe_interruption(self, event: NetworkEvent) -> None:
        details = dict(event.details or {})
        subtype = str(details.get("subtype") or details.get("type") or "")
        if subtype in {"deauth", "disassoc", "ra_injection", "arp_spoof", "gw_impersonation"}:
            self.interruptions.append({
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "subtype": subtype,
                "test_id": event.test_id,
                "scenario_id": event.scenario_id,
                "src_addr": event.src_addr,
                "dst_addr": event.dst_addr,
            })

    # ------------------------------------------------------------------
    def site_sessions(self) -> list[dict[str, Any]]:
        """Group destination activity into recurring site sessions."""
        sessions: list[dict[str, Any]] = []
        for domain, events in self.domain_events.items():
            timestamps = sorted(e.timestamp for e in events)
            flows = sorted({_flow_key(e) for e in events if e.src_addr or e.dst_addr})
            sessions.append({
                "domain": domain,
                "observations": len(events),
                "first_seen": timestamps[0].isoformat() if timestamps else None,
                "last_seen": timestamps[-1].isoformat() if timestamps else None,
                "flows": flows,
                "tls": any(e.category is EventCategory.TLS for e in events),
                "cleartext_http": any(e.category is EventCategory.HTTP for e in events),
            })
        sessions.sort(key=lambda s: s["first_seen"] or "")
        return sessions

    def redirect_chains(self) -> list[dict[str, Any]]:
        chains: list[dict[str, Any]] = []
        by_location: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for entries in self.http_by_flow.values():
            for entry in entries:
                if entry.get("status") in {301, 302, 303, 307, 308} and entry.get("location"):
                    by_location[str(entry["location"]).lower()].append(entry)
        for entries in self.http_by_flow.values():
            for entry in entries:
                target = str(entry.get("target") or "").lower()
                location = str(entry.get("location") or "").lower()
                if entry.get("status") in {301, 302, 303, 307, 308} and location:
                    chains.append({
                        "from": target,
                        "to": location,
                        "status": entry["status"],
                        "cleartext": True,
                        "event_id": entry["event_id"],
                        "downgrade_risk": location.startswith("http://"),
                    })
        return chains

    def relationship_graph(self) -> dict[str, Any]:
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        seen_nodes: set[str] = set()

        def add_node(node_id: str, kind: str, label: str, **attrs: Any) -> None:
            if node_id in seen_nodes:
                return
            seen_nodes.add(node_id)
            nodes.append({"id": node_id, "kind": kind, "label": label, **attrs})

        for name, ips in self.dns_name_to_ips.items():
            add_node(f"domain:{name}", "domain", name)
            for ip in sorted(ips):
                add_node(f"ip:{ip}", "ip", ip)
                edges.append({"from": f"domain:{name}", "to": f"ip:{ip}", "kind": "resolves_to"})
        for flow_key, tls in self.tls_by_flow.items():
            sni = tls.get("sni")
            if sni:
                add_node(f"domain:{sni}", "domain", sni)
                edges.append({"from": f"flow:{flow_key}", "to": f"domain:{sni}", "kind": "tls_sni"})
        for domain, observations in self.cookie_observations.items():
            add_node(f"cookies:{domain}", "cookies", f"cookies observed for {domain}")
            edges.append({"from": f"domain:{domain}", "to": f"cookies:{domain}",
                          "kind": "cleartext_cookie_observation",
                          "count": len(observations)})
        for event in self.firewall_events:
            add_node(f"firewall:{event.event_id}", "firewall", event.summary)
            if event.test_id:
                add_node(f"test:{event.test_id}", "test", event.test_id)
                edges.append({"from": f"test:{event.test_id}", "to": f"firewall:{event.event_id}",
                              "kind": "firewall_report"})
        return {"nodes": nodes, "edges": edges}


class LongitudinalAnalyzer:
    """Entry point: ingest a whole assessment and produce correlated reports."""

    def __init__(self, *, clock: Any | None = None) -> None:
        self.clock = clock
        self.events: list[NetworkEvent] = []
        self.correlator = SessionCorrelator()
        self.findings: list[Finding] = []

    def ingest(self, events: Iterable[NetworkEvent]) -> None:
        for event in sorted(events, key=lambda e: e.timestamp):
            self.events.append(event)
            self.correlator.add(event)
        self._derive_findings()

    # ------------------------------------------------------------------
    def _derive_findings(self) -> None:
        self.findings = []
        for name, ips in self.correlator.dns_name_to_ips.items():
            if len(ips) > 1:
                self.findings.append(Finding(
                    kind="dns_multi_answer",
                    summary=f"{name} resolved to {len(ips)} addresses ({', '.join(sorted(ips))})",
                    confidence="low",
                    caveat="multiple answers may be normal load balancing or a manipulation",
                ))
        for ip, names in self.correlator.dns_ip_to_names.items():
            if len(names) > 1:
                self.findings.append(Finding(
                    kind="shared_destination",
                    summary=f"{ip} serves {len(names)} observed names",
                    confidence="low",
                ))
        for chain in self.correlator.redirect_chains():
            if chain["downgrade_risk"]:
                self.findings.append(Finding(
                    kind="cleartext_redirect",
                    summary=f"redirect from {chain['from']} to {chain['to']} over cleartext HTTP",
                    confidence="medium",
                    evidence_refs=[chain["event_id"]],
                ))
        for domain, observations in self.correlator.cookie_observations.items():
            names = sorted({n for o in observations for n in o["names"]})
            self.findings.append(Finding(
                kind="cleartext_cookie_observation",
                summary=(
                    f"cookie header observed in cleartext for {domain}; "
                    f"names={names}; values were present on the wire"
                ),
                confidence="high" if observations else "none",
                evidence_refs=[o["event_id"] for o in observations],
                caveat="only names and the fact of exposure are reported here; values are handled by the cookie exposure engine",
            ))
        for domain, events in self.correlator.domain_events.items():
            if any(e.category is EventCategory.TLS for e in events) and \
                    any(e.category is EventCategory.HTTP for e in events):
                self.findings.append(Finding(
                    kind="mixed_usage",
                    summary=f"{domain} was contacted over both TLS and cleartext HTTP",
                    confidence="medium",
                    caveat="does not by itself prove a downgrade; see the downgrade resistance report",
                ))
        for interruption in self.correlator.interruptions:
            self.findings.append(Finding(
                kind="connection_disruption",
                summary=f"{interruption['subtype']} observed during test {interruption['test_id']}",
                confidence="medium",
                evidence_refs=[interruption["event_id"]],
                caveat="disruption is not evidence of interception",
            ))
        if self.correlator.firewall_events:
            self.findings.append(Finding(
                kind="firewall_reports_present",
                summary=f"{len(self.correlator.firewall_events)} firewall-reported event(s) recorded",
                confidence="high",
                caveat="a firewall report describes a firewall decision, not an attack outcome",
            ))

    # ------------------------------------------------------------------
    def timeline(self) -> list[dict[str, Any]]:
        return [
            {
                "timestamp": e.timestamp.isoformat(),
                "event_id": e.event_id,
                "category": e.category.value,
                "source": e.source.value,
                "severity": e.severity.value,
                "summary": e.summary,
                "session_id": e.session_id,
                "test_id": e.test_id,
                "scenario_id": e.scenario_id,
                "device_id": e.device_id,
                "protocol": e.protocol,
                "src_addr": e.src_addr,
                "dst_addr": e.dst_addr,
                "dst_port": e.dst_port,
                "evidence_ref": e.evidence_ref,
            }
            for e in sorted(self.events, key=lambda e: e.timestamp)
        ]

    def summary(self) -> dict[str, Any]:
        sources: dict[str, int] = {}
        categories: dict[str, int] = {}
        for event in self.events:
            sources[event.source.value] = sources.get(event.source.value, 0) + 1
            categories[event.category.value] = categories.get(event.category.value, 0) + 1
        return {
            "events": len(self.events),
            "sources": sources,
            "categories": categories,
            "domains_observed": len(self.correlator.domain_events),
            "flows": len(self.correlator.flows),
            "site_sessions": len(self.correlator.site_sessions()),
            "firewall_events": len(self.correlator.firewall_events),
            "interruptions": len(self.correlator.interruptions),
            "findings": len(self.findings),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "timeline": self.timeline(),
            "site_sessions": self.correlator.site_sessions(),
            "redirect_chains": self.correlator.redirect_chains(),
            "relationship_graph": self.correlator.relationship_graph(),
            "findings": [f.to_dict() for f in self.findings],
            "limitations": [
                "Correlation describes patterns and sequencing, not authenticated identity.",
                "A specific user or session is never asserted unless a plaintext identifier "
                "in the captured evidence supports it.",
                "Encrypted payloads contribute metadata only; no content is inferred.",
                "Missing telemetry is reported as missing and is not treated as absence of activity.",
            ],
        }

    def to_json(self) -> str:
        import json

        return json.dumps(self.to_dict(), indent=2, sort_keys=True, default=str)


def _flow_key(event: NetworkEvent) -> str:
    return "|".join(str(x) for x in (
        event.src_addr, event.src_port, event.dst_addr, event.dst_port, event.protocol,
    ))


def _parse_cookie_pairs(value: str) -> list[tuple[str, str]]:
    from ..protocols import http

    try:
        return http.parse_cookie_header(value)
    except Exception:  # pragma: no cover - defensive
        return []
