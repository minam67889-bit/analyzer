from __future__ import annotations

from datetime import UTC, datetime

from adversarylab.analysis.views import (
    attacker_view,
    attacker_visible_inventory,
    defender_view,
    dual_view,
)
from adversarylab.core.results import (
    BlockCause,
    Confidence,
    ExecutionMode,
    Observation,
    TestResult,
    Verdict,
)


def _result(test_id: str, observations: list[Observation], *,
            verdict: Verdict = Verdict.INCONCLUSIVE) -> TestResult:
    return TestResult(
        result_id=f"res-{test_id}", test_id=test_id, scenario_id=None,
        verdict=verdict, confidence=Confidence.LOW, block_cause=BlockCause.NONE,
        execution_mode=ExecutionMode.REAL_NETWORK, rationale="test",
        observations=observations,
    )


def test_attacker_view_lists_only_network_observable_data():
    result = _result("T", [
        Observation("packet_capture", "detected", datetime.now(UTC), "tls",
                    details={"sni": "secure.lab.test", "dst": "10.10.0.9"}),
        Observation("lab_server", "cookie_exposed", datetime.now(UTC), "cookie",
                    details={"host": "plain.lab.test", "names": ["session_id"]}),
    ])
    view = attacker_view(result)
    assert "plain.lab.test" in view["observable_domains"]
    assert "secure.lab.test" in view["tls_domains_metadata_only"]
    assert "session_id" in view["plaintext_cookie_names"]
    assert "TLS application payloads" in view["not_observable"]


def test_defender_view_separates_block_from_allow():
    result = _result("T", [
        Observation("firewall", "firewall_block", datetime.now(UTC), "blocked",
                    details={"action": "block"}),
        Observation("packet_capture", "detected", datetime.now(UTC), "rst",
                    details={"kind": "rst"}),
    ], verdict=Verdict.DETECTED_AND_BLOCKED)
    view = defender_view(result)
    assert view["blocked_count"] == 1
    assert view["corroborated_by_independent_capture"] is True
    assert view["block_cause"] == "NONE"  # cause comes from the result, not the view


def test_dual_view_keeps_perspectives_separate():
    result = _result("T", [
        Observation("packet_capture", "detected", datetime.now(UTC), "seen",
                    details={"sni": "x.lab.test"}),
    ])
    dual = dual_view(result)
    assert dual["attacker"]["perspective"] == "attacker"
    assert dual["defender"]["perspective"] == "defender"
    assert dual["independence_note"]


def test_inventory_aggregates_across_results():
    results = [
        _result("A", [Observation("packet_capture", "detected", datetime.now(UTC), "x",
                                 details={"host": "a.lab.test"})]),
        _result("B", [Observation("packet_capture", "detected", datetime.now(UTC), "y",
                                 details={"host": "b.lab.test"})]),
    ]
    inventory = attacker_visible_inventory(results)
    assert set(inventory["domains_observed"]) == {"a.lab.test", "b.lab.test"}
