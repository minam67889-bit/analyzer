from __future__ import annotations

from adversarylab.analysis.longitudinal import LongitudinalAnalyzer, SessionCorrelator
from adversarylab.core.events import EventCategory, EventSeverity, EventSource, make_event


def _dns_event(qname: str, answers: list[dict], *, test_id: str | None = None):
    return make_event(
        session_id="s", test_id=test_id, category=EventCategory.DNS,
        source=EventSource.PACKET_CAPTURE, summary=f"DNS {qname}", protocol="dns",
        src_addr="10.10.0.50", dst_addr="10.10.0.1", dst_port=53,
        details={"qname": qname, "answers": answers},
    )


def _tls_event(sni: str):
    return make_event(
        session_id="s", category=EventCategory.TLS, source=EventSource.PACKET_CAPTURE,
        summary=f"TLS {sni}", protocol="tls", src_addr="10.10.0.50",
        dst_addr="10.10.0.9", dst_port=443, details={"sni": sni, "version": "TLSv1.3"},
    )


def test_dns_correlation_maps_names_to_addresses():
    analyzer = LongitudinalAnalyzer()
    analyzer.ingest([
        _dns_event("api.lab.test", [{"address": "10.10.0.50"}]),
        _dns_event("api.lab.test", [{"address": "10.10.0.51"}]),
    ])
    assert analyzer.correlator.dns_name_to_ips["api.lab.test"] == {"10.10.0.50", "10.10.0.51"}
    sessions = analyzer.correlator.site_sessions()
    assert sessions[0]["domain"] == "api.lab.test"
    kinds = {f.kind for f in analyzer.findings}
    assert "dns_multi_answer" in kinds


def test_tls_metadata_does_not_become_content():
    analyzer = LongitudinalAnalyzer()
    analyzer.ingest([_tls_event("secure.lab.test")])
    sessions = analyzer.correlator.site_sessions()
    assert sessions[0]["tls"] is True
    assert sessions[0]["cleartext_http"] is False
    payload = analyzer.to_dict()
    assert payload["summary"]["domains_observed"] >= 1


def test_relationship_graph_links_domain_and_cookies():
    analyzer = LongitudinalAnalyzer()
    http = make_event(
        session_id="s", category=EventCategory.HTTP, source=EventSource.PACKET_CAPTURE,
        summary="http", protocol="http", src_addr="10.10.0.50", dst_addr="10.10.0.1",
        dst_port=80,
        details={"direction": "request", "host": "plain.lab.test",
                 "headers": {"cookie": "session_id=abc"}},
    )
    analyzer.ingest([_dns_event("plain.lab.test", [{"address": "10.10.0.1"}]), http])
    graph = analyzer.correlator.relationship_graph()
    edge_kinds = {e["kind"] for e in graph["edges"]}
    assert "resolves_to" in edge_kinds
    assert "cleartext_cookie_observation" in edge_kinds


def test_redirect_chain_flags_downgrade_risk():
    correlator = SessionCorrelator()
    correlator._add_http(make_event(
        session_id="s", category=EventCategory.HTTP, source=EventSource.PACKET_CAPTURE,
        summary="302", protocol="http", src_addr="10.10.0.50", dst_addr="10.10.0.1",
        dst_port=80,
        details={"direction": "response", "status": 302, "location": "http://plain.lab.test/x"},
    ))
    chains = correlator.redirect_chains()
    assert chains and chains[0]["downgrade_risk"] is True


def test_firewall_events_are_counted_but_not_outcomes():
    analyzer = LongitudinalAnalyzer()
    analyzer.ingest([
        make_event(session_id="s", category=EventCategory.FIREWALL, source=EventSource.FIREWALL,
                   severity=EventSeverity.ALERT, summary="blocked", details={"action": "block"}),
    ])
    assert analyzer.summary()["firewall_events"] == 1
    assert any(f.kind == "firewall_reports_present" for f in analyzer.findings)


def test_timeline_is_sorted_and_carries_evidence_refs():
    analyzer = LongitudinalAnalyzer()
    analyzer.ingest([
        _dns_event("a.lab.test", [], test_id="DNS-SPOOF-A"),
        _tls_event("b.lab.test"),
    ])
    timeline = analyzer.timeline()
    assert len(timeline) == 2
    assert timeline[0]["timestamp"] <= timeline[1]["timestamp"]
