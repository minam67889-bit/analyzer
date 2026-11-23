from __future__ import annotations

import json

from adversarylab.adversary.orchestrator import AssessmentResult
from adversarylab.core.results import BlockCause, Confidence, ExecutionMode, TestResult, Verdict
from adversarylab.reporting.report import (
    ReportGenerator,
    render_coverage_table,
    render_results_table,
)
from adversarylab.tests.registry import CoverageRow


def _result(test_id: str, verdict: Verdict, confidence: Confidence = Confidence.LOW) -> TestResult:
    return TestResult(
        result_id=f"res-{test_id}",
        test_id=test_id,
        scenario_id=None,
        verdict=verdict,
        confidence=confidence,
        block_cause=BlockCause.NONE,
        execution_mode=ExecutionMode.REAL_NETWORK,
        rationale="unit-test rationale",
        started_at=None,
        ended_at=None,
    )


def _assessment() -> AssessmentResult:
    result = AssessmentResult(
        session_id="sess-test",
        status="completed",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:01:00+00:00",
        environment={"platform": "test"},
    )
    result.results.append(_result("DNS-SPOOF-A", Verdict.DETECTED_AND_BLOCKED, Confidence.HIGH))
    result.results.append(_result("HTTP-CLEARTEXT", Verdict.INCONCLUSIVE, Confidence.LOW))
    result.coverage.append(CoverageRow(
        test_id="DNS-SPOOF-A", name="DNS A spoof", category="dns",
        status="EXECUTED", reason="ran", execution_mode="REAL_NETWORK",
        verdict="DETECTED_AND_BLOCKED", confidence="HIGH",
    ))
    result.coverage.append(CoverageRow(
        test_id="TLS-PINNING", name="TLS pinning", category="tls",
        status="SKIPPED", reason="capability missing", execution_mode="",
        verdict="", confidence="",
    ))
    return result


def test_json_and_csv_exports(tmp_path):
    result = _assessment()
    generator = ReportGenerator(result)
    payload = generator.to_json()
    assert "sess-test" in payload
    data = json.loads(payload)
    assert len(data["results"]) == 2
    rows = generator.to_csv_rows()
    assert len(rows) == 2
    assert rows[0]["test_id"] == "DNS-SPOOF-A"


def test_html_report_is_self_contained(tmp_path):
    result = _assessment()
    generator = ReportGenerator(result)
    html = generator.to_html(evidence_records=[])
    assert "<html" in html.lower()
    assert "DETECTED_AND_BLOCKED" in html
    assert "<script" not in html.lower()


def test_tables_render():
    result = _assessment()
    coverage = render_coverage_table(result.coverage)
    assert "DNS-SPOOF-A" in coverage and "EXECUTED" in coverage
    results = render_results_table(result.results)
    assert "INCONCLUSIVE" in results


def test_report_file_written(tmp_path):
    result = _assessment()
    generator = ReportGenerator(result)
    paths = generator.write(tmp_path / "out", evidence_records=[])
    html = paths["html"].read_text(encoding="utf-8")
    assert html.startswith("<!DOCTYPE html>")
    assert paths["json"].exists() and paths["csv"].exists()
