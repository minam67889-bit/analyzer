from __future__ import annotations

from datetime import UTC, datetime

from adversarylab.core.results import (
    BlockCause,
    Confidence,
    EvaluationPolicy,
    ExecutionMode,
    Observation,
    TestResult,
    Verdict,
    VerdictEngine,
)


def _obs(source: str, kind: str, summary: str = "", **details) -> Observation:
    return Observation(source, kind, datetime.now(UTC), summary, details=details)


def _evaluate(observations, *, expect_block: bool) -> TestResult:
    engine = VerdictEngine()
    return engine.evaluate(
        test_id="T",
        scenario_id=None,
        observations=observations,
        execution_mode=ExecutionMode.REAL_NETWORK,
        policy=EvaluationPolicy(expect_block=expect_block),
    )


def test_missing_telemetry_is_never_pass():
    result = _evaluate([_obs("packet_capture", "no_observations", "nothing")], expect_block=True)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.confidence is Confidence.LOW


def test_expected_allow_without_any_traffic_is_inconclusive():
    result = _evaluate([
        _obs("lab", "endpoint_applied", "endpoint created"),
        _obs("lab_server", "no_observations", "no hits"),
    ], expect_block=False)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.block_cause is BlockCause.NONE


def test_expected_allow_with_only_setup_observations_is_inconclusive():
    result = _evaluate([
        _obs("lab", "http_endpoint_applied", "endpoint created"),
        _obs("lab_server", "sink_no_hit", "sink got nothing"),
    ], expect_block=False)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.block_cause is BlockCause.NONE


def test_expected_allow_with_network_failure_is_inconclusive():
    result = _evaluate([_obs("packet_capture", "timeout", "no reply")], expect_block=False)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.block_cause is BlockCause.TIMEOUT


def test_expected_allow_with_block_evidence_fails():
    result = _evaluate([_obs("firewall", "firewall_block", "blocked", action="block")],
                       expect_block=False)
    assert result.verdict is Verdict.FAIL
    assert result.block_cause is not BlockCause.NONE


def test_expected_allow_with_sink_hit_passes():
    result = _evaluate([
        _obs("lab_server", "allowed", "traffic arrived"),
        _obs("packet_capture", "detected", "flow observed"),
    ], expect_block=False)
    assert result.verdict is Verdict.PASS


def test_firewall_confirmed_block_is_detected_and_blocked():
    result = _evaluate([
        _obs("firewall", "firewall_block", "blocked", action="block"),
        _obs("packet_capture", "detected", "rst observed"),
    ], expect_block=True)
    assert result.verdict is Verdict.DETECTED_AND_BLOCKED
    assert result.block_cause is BlockCause.FIREWALL_CONFIRMED


def test_block_without_firewall_confirmation_is_inconclusive_when_required():
    result = _evaluate([_obs("packet_capture", "blocked", "rst observed")], expect_block=True)
    assert result.verdict is Verdict.INCONCLUSIVE


def test_network_failure_is_not_a_firewall_block():
    result = _evaluate([_obs("packet_capture", "timeout", "no reply")], expect_block=True)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.block_cause is BlockCause.TIMEOUT


def test_unsupported_execution_mode_is_not_a_pass():
    engine = VerdictEngine()
    result = engine.evaluate(
        test_id="T", scenario_id=None, observations=[],
        execution_mode=ExecutionMode.UNSUPPORTED,
        policy=EvaluationPolicy(expect_block=True),
    )
    assert result.verdict is Verdict.UNSUPPORTED


def test_pass_requires_positive_evidence():
    """A PASS must never be produced from an empty observation list."""
    result = _evaluate([], expect_block=False)
    assert result.verdict is not Verdict.PASS
    assert result.verdict is Verdict.INCONCLUSIVE
