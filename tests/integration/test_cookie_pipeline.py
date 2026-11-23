from __future__ import annotations

import http.client
import socket

from adversarylab.adversary.actions import ServiceBackedActionRunner
from adversarylab.config.schema import default_config
from adversarylab.cookies.engine import CookieExposureEngine
from adversarylab.cookies.ground_truth import CookieGroundTruth
from adversarylab.cookies.model import CookieClassification, CookieSpec, SameSite
from adversarylab.cookies.report import CookieExposureReport
from adversarylab.core.bus import EventBus, RecordingSink
from adversarylab.services.http_server import CookieRouteConfig, LabHttpServer
from adversarylab.tests.catalog import build_default_registry


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _collect_events():
    bus = EventBus()
    sink = RecordingSink()
    bus.subscribe(sink)
    return bus, sink


def test_lab_site_plaintext_cookie_is_attacker_observable(tmp_path):
    port = _free_port()
    bus, sink = _collect_events()
    server = LabHttpServer(bind_addr="127.0.0.1", port=port, bus=bus.publish)
    server.add_cookie_route(
        "plain.lab.test", "/login",
        [CookieRouteConfig("session_id", "synthetic-plain-0001", httponly=False,
                           samesite="Lax", purpose="session cookie")],
        body="<html>login</html>",
    )
    store = CookieGroundTruth(tmp_path / "gt.db")
    store.register(CookieSpec(
        site_id="plain", domain="plain.lab.test", name="session_id",
        value="synthetic-plain-0001", httponly=False, samesite=SameSite.LAX, session=True,
    ))
    server.start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/login", headers={
            "Host": "plain.lab.test",
            "Cookie": "session_id=synthetic-plain-0001",
        })
        response = conn.getresponse()
        response.read()
        assert response.status == 200
        set_cookie = response.getheader("Set-Cookie")
        assert set_cookie and "synthetic-plain-0001" in set_cookie
    finally:
        server.stop()

    engine = CookieExposureEngine(store)
    engine.ingest_events(sink.events)
    results = {o.site_id: o for o in engine.finalize()}
    plain = results["plain"]
    assert plain.classification is CookieClassification.ATTACKER_OBSERVED_PLAINTEXT
    assert plain.value_available is True
    assert plain.verified_against_ground_truth is True
    assert plain.observed_via == "plaintext_http_request"
    assert plain.evidence_ref is None  # capture-side evidence refs are attached by the pipeline


def test_orchestrator_end_to_end_plaintext_exposure(tmp_path, bus, db, all_capabilities, clock):
    """Full path: lab endpoint + real client traffic -> attacker-observed cookie."""

    from adversarylab.adversary.orchestrator import Orchestrator

    port = _free_port()
    config = default_config()
    config.tests.observation_window_seconds = 0.05
    orchestrator = Orchestrator(
        config=config, registry=build_default_registry(), capabilities=all_capabilities,
        bus=bus, db=db, evidence_root=tmp_path / "evidence",
        action_runner=ServiceBackedActionRunner(bus=bus.publish, session_id=""),
        clock=clock,
    )
    orchestrator.create_session()
    orchestrator.prepare()
    result = orchestrator.run_test("COOKIE-PLAINTEXT-EXPOSURE", params={"port": port})
    assert result.test_id == "COOKIE-PLAINTEXT-EXPOSURE"

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    conn.request("GET", "/login", headers={
        "Host": "cookies.lab.test",
        "Cookie": "session_id=syn-session-0001; cart_id=syn-cart-0002",
    })
    response = conn.getresponse()
    response.read()
    assert response.status == 200

    events = bus.history()
    assert events, "lab server must publish HTTP events to the bus"
    engine = CookieExposureEngine(orchestrator.cookie_ground_truth)
    engine.ingest_events(events)
    observations = {o.name: o for o in engine.finalize()}
    assert observations["session_id"].classification is CookieClassification.ATTACKER_OBSERVED_PLAINTEXT
    assert observations["session_id"].verified_against_ground_truth is True
    assert observations["session_id"].observed_value == "syn-session-0001"
    # The finding must reference reproducible evidence, not just a summary.
    ref = observations["session_id"].evidence_ref
    assert ref
    refs = {e.evidence_ref for e in events} | {
        (e.details or {}).get("evidence_ref") for e in events
    }
    assert ref in refs
    evidence_ids = {r.evidence_id for r in orchestrator.evidence.records}
    assert ref in evidence_ids
    assert any(r.evidence_id == ref and r.test_id == "COOKIE-PLAINTEXT-EXPOSURE" for r in orchestrator.evidence.records)
    # The connection tuple is recorded alongside the value.
    assert observations["session_id"].connection.get("dst_port") == port


def test_attacker_inventory_never_prints_a_raw_cookie_value(
    tmp_path, bus, db, all_capabilities, clock
):
    """End-to-end: an observed plaintext value must not reach the attacker-facing report."""
    from adversarylab.adversary.orchestrator import Orchestrator
    from adversarylab.reporting.extra_reports import ReportBundle

    port = _free_port()
    config = default_config()
    config.tests.observation_window_seconds = 0.05
    orchestrator = Orchestrator(
        config=config, registry=build_default_registry(), capabilities=all_capabilities,
        bus=bus, db=db, evidence_root=tmp_path / "evidence",
        action_runner=ServiceBackedActionRunner(bus=bus.publish, session_id=""),
        clock=clock,
    )
    orchestrator.create_session()
    orchestrator.prepare()
    orchestrator.cookie_ground_truth.register(CookieSpec(
        site_id="cookie-plaintext", domain="cookies.lab.test", name="session_id",
        value="syn-secret-7f3a", httponly=True, samesite=SameSite.LAX, session=True,
    ))
    orchestrator.run_test("COOKIE-PLAINTEXT-EXPOSURE", params={"port": port})

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    conn.request("GET", "/login", headers={
        "Host": "cookies.lab.test", "Cookie": "session_id=syn-secret-7f3a",
    })
    response = conn.getresponse()
    response.read()
    assert response.status == 200

    from adversarylab.adversary.orchestrator import AssessmentResult

    assessment = AssessmentResult(
        session_id=orchestrator.session_id, status="running", started_at=clock.now()
    )
    orchestrator._analyse(assessment)
    assert assessment.cookie_exposure["summary"]["attacker_observed_values"] >= 1
    out = tmp_path / "reports"
    ReportBundle(assessment).write(out)

    inventory_html = (out / "attacker_visible_data_inventory.html").read_text()
    inventory_json = (out / "attacker_visible_data_inventory.json").read_text()
    cookie_html = (out / "cookie_exposure.html").read_text()
    for document in (inventory_html, inventory_json, cookie_html):
        assert "syn-secret-7f3a" not in document
    # The redacted form is still verifiable: prefix + stable digest.
    assert "syn-" in inventory_html
    assert "sha256:" in cookie_html


def test_report_redacts_by_default(tmp_path):
    store = CookieGroundTruth(tmp_path / "gt.db")
    store.register(CookieSpec(
        site_id="plain", domain="plain.lab.test", name="session_id",
        value="synthetic-plain-0002", session=True,
    ))
    engine = CookieExposureEngine(store)
    from adversarylab.core.events import EventCategory, EventSource, make_event

    engine.ingest_event(make_event(
        session_id="s", category=EventCategory.HTTP, source=EventSource.PACKET_CAPTURE,
        summary="http", protocol="http", src_addr="10.10.0.50", dst_addr="10.10.0.1",
        dst_port=80,
        details={"direction": "request", "host": "plain.lab.test",
                 "headers": {"cookie": "session_id=synthetic-plain-0002"}},
    ))
    report = CookieExposureReport(engine.finalize())
    html = report.to_html()
    assert "synthetic-plain-0002" not in html
    assert "sha256:" in html
    assert "Attacker-observed (plaintext)" in html
    paths = report.write(tmp_path / "report")
    assert paths["html"].exists() and paths["csv"].exists() and paths["json"].exists()
    assert "synthetic-plain-0002" not in paths["csv"].read_text()


def test_report_can_reveal_synthetic_values_on_request(tmp_path):
    store = CookieGroundTruth(tmp_path / "gt.db")
    store.register(CookieSpec(
        site_id="plain", domain="plain.lab.test", name="session_id",
        value="synthetic-plain-0003", session=True,
    ))
    engine = CookieExposureEngine(store)
    from adversarylab.core.events import EventCategory, EventSource, make_event

    engine.ingest_event(make_event(
        session_id="s", category=EventCategory.HTTP, source=EventSource.PACKET_CAPTURE,
        summary="http", protocol="http", src_addr="10.10.0.50", dst_addr="10.10.0.1",
        dst_port=80,
        details={"direction": "request", "host": "plain.lab.test",
                 "headers": {"cookie": "session_id=synthetic-plain-0003"}},
    ))
    report = CookieExposureReport(engine.finalize(), reveal_values=True)
    assert "synthetic-plain-0003" in report.to_html()
