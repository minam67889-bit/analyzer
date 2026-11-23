from __future__ import annotations

import json

from adversarylab.adversary.orchestrator import AssessmentResult
from adversarylab.core.results import BlockCause, Confidence, ExecutionMode, TestResult, Verdict
from adversarylab.reporting.extra_reports import ReportBundle


def _result(test_id: str, verdict: Verdict = Verdict.INCONCLUSIVE) -> TestResult:
    return TestResult(
        result_id=f"res-{test_id}", test_id=test_id, scenario_id=None,
        verdict=verdict, confidence=Confidence.LOW, block_cause=BlockCause.NONE,
        execution_mode=ExecutionMode.REAL_NETWORK, rationale="unit-test rationale",
    )


def _assessment() -> AssessmentResult:
    result = AssessmentResult(
        session_id="sess-reports", status="completed",
        started_at="2026-01-01T00:00:00+00:00", finished_at="2026-01-01T00:05:00+00:00",
        environment={"platform": "test"},
    )
    result.results = [
        _result("COOKIE-PLAINTEXT-EXPOSURE", Verdict.PASS),
        _result("HTTP-DOWNGRADE"),
        _result("TLS-WRONG-CERT"),
    ]
    result.campaigns = [{
        "campaign_id": "cookie-exposure-plaintext", "status": "completed",
        "explanation": "objective reached", "objective_reached": True,
        "stages": [{"stage": {"name": "Reconnaissance"}, "conditions_before": [],
                    "feasible": True, "result": None, "note": ""}],
    }]
    result.cookie_exposure = {
        "summary": {"total_cookie_outcomes": 1, "attacker_observed_values": 1},
        "observations": [{
            "site_id": "cookie-plaintext", "domain": "cookies.lab.test", "name": "session_id",
            "classification": "attacker_observed_plaintext",
            "observed_value": "syn-session-0001", "value_available": True,
            "observed_via": "plaintext_http_request", "connection": {},
            "evidence_ref": "evt-1", "attributes": {"secure": False},
            "verified_against_ground_truth": True, "ground_truth_value_known": True,
            "notes": "",
        }],
    }
    result.longitudinal = {
        "summary": {"events": 3, "domains_observed": 1},
        "timeline": [{"timestamp": "2026-01-01T00:00:01+00:00", "category": "http",
                       "source": "packet_capture", "severity": "info", "test_id": None,
                       "summary": "http", "dst_addr": "10.10.0.1", "dst_port": 80,
                       "event_id": "evt-1", "evidence_ref": None}],
        "site_sessions": [{"domain": "cookies.lab.test", "observations": 1,
                           "first_seen": "2026-01-01T00:00:01+00:00",
                           "last_seen": "2026-01-01T00:00:01+00:00",
                           "tls": False, "cleartext_http": True}],
        "redirect_chains": [], "findings": [],
        "relationship_graph": {"nodes": [], "edges": []},
    }
    return result


def test_bundle_writes_all_nine_reports(tmp_path):
    paths = ReportBundle(_assessment()).write(tmp_path / "mandatory")
    assert len(paths) == 9
    for name, path in paths.items():
        assert path.exists(), name
        assert path.suffix == ".html"
        assert (path.parent / f"{name}.json").exists()
        document = path.read_text(encoding="utf-8")
        assert document.startswith("<!DOCTYPE html>")
        assert "<script" not in document.lower()


def test_cookie_report_redacts_value_by_default(tmp_path):
    paths = ReportBundle(_assessment()).write(tmp_path / "m")
    html = paths["cookie_exposure"].read_text(encoding="utf-8")
    assert "syn-session-0001" not in html
    payload = json.loads((paths["cookie_exposure"].parent / "cookie_exposure.json").read_text())
    assert payload["observations"][0]["observed_value"] is None or \
        "syn-session-0001" not in str(payload["observations"][0]["observed_value"])


def test_attacker_inventory_redacts_even_when_operator_opted_in(tmp_path):
    """The attacker-facing inventory is redacted unconditionally; only the
    operator cookie-exposure report honours reveal_cookie_values."""
    paths = ReportBundle(_assessment(), reveal_cookie_values=True).write(tmp_path / "m")
    inventory = paths["attacker_visible_data_inventory"].read_text(encoding="utf-8")
    assert "syn-session-0001" not in inventory
    assert "sha256:" in inventory
    cookie = paths["cookie_exposure"].read_text(encoding="utf-8")
    assert "syn-session-0001" in cookie


def test_defender_report_lists_missing_telemetry(tmp_path):
    paths = ReportBundle(_assessment()).write(tmp_path / "m")
    html = paths["defender_detection_prevention"].read_text(encoding="utf-8")
    assert "Missing defender telemetry" in html


def test_campaign_report_contains_chain(tmp_path):
    paths = ReportBundle(_assessment()).write(tmp_path / "m")
    html = paths["multi_stage_attack_chain"].read_text(encoding="utf-8")
    assert "cookie-exposure-plaintext" in html
    assert "Objective reached" in html
