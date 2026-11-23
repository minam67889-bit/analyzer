from __future__ import annotations

from datetime import UTC, datetime

from adversarylab.core.results import (
    BlockCause,
    Confidence,
    EvaluationPolicy,
    ExecutionMode,
    Observation,
    Verdict,
    VerdictEngine,
)


def obs(source, kind, summary="obs", **details):
    return Observation(source, kind, datetime(2026, 1, 1, tzinfo=UTC), summary, details)


def test_expected_block_confirmed_high_confidence():
    engine = VerdictEngine()
    policy = EvaluationPolicy(expect_block=True, require_firewall_confirmation=True)
    result = engine.evaluate(
        test_id="T", scenario_id=None,
        observations=[obs("packet_capture", "blocked"), obs("firewall", "firewall_block")],
        execution_mode=ExecutionMode.REAL_NETWORK, policy=policy,
    )
    assert result.verdict is Verdict.DETECTED_AND_BLOCKED
    assert result.block_cause is BlockCause.FIREWALL_CONFIRMED
    assert result.confidence is Confidence.HIGH


def test_expected_block_without_firewall_evidence_is_inconclusive():
    engine = VerdictEngine()
    policy = EvaluationPolicy(expect_block=True, require_firewall_confirmation=True)
    result = engine.evaluate(
        test_id="T", scenario_id=None,
        observations=[obs("packet_capture", "blocked")],
        execution_mode=ExecutionMode.REAL_NETWORK, policy=policy,
    )
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.block_cause is BlockCause.UNKNOWN


def test_allowed_when_block_expected_fails():
    engine = VerdictEngine()
    policy = EvaluationPolicy(expect_block=True)
    result = engine.evaluate(
        test_id="T", scenario_id=None,
        observations=[obs("lab_server", "sink_hit")],
        execution_mode=ExecutionMode.REAL_NETWORK, policy=policy,
    )
    assert result.verdict is Verdict.FAIL
    assert result.block_cause is BlockCause.NONE


def test_expected_allow_pass():
    engine = VerdictEngine()
    policy = EvaluationPolicy(expect_block=False)
    result = engine.evaluate(
        test_id="T", scenario_id=None,
        observations=[obs("lab_server", "allowed")],
        execution_mode=ExecutionMode.REAL_NETWORK, policy=policy,
    )
    assert result.verdict is Verdict.PASS


def test_no_observations_is_inconclusive_never_pass():
    engine = VerdictEngine()
    result = engine.evaluate(
        test_id="T", scenario_id=None, observations=[],
        execution_mode=ExecutionMode.REAL_NETWORK,
        policy=EvaluationPolicy(expect_block=True),
    )
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "absence of evidence" in result.rationale


def test_simulation_downgrades_to_partially_verified():
    engine = VerdictEngine()
    result = engine.evaluate(
        test_id="T", scenario_id=None,
        observations=[obs("firewall", "firewall_block"), obs("packet_capture", "blocked")],
        execution_mode=ExecutionMode.PROTOCOL_SIMULATION,
        policy=EvaluationPolicy(expect_block=True),
    )
    assert result.verdict is Verdict.PARTIALLY_VERIFIED
    assert result.confidence is Confidence.LOW
    assert any("not proof" in lim for lim in result.limitations)


def test_unsupported_mode():
    engine = VerdictEngine()
    result = engine.evaluate(
        test_id="T", scenario_id=None,
        observations=[obs("packet_capture", "blocked")],
        execution_mode=ExecutionMode.UNSUPPORTED,
        policy=EvaluationPolicy(expect_block=True),
    )
    assert result.verdict is Verdict.UNSUPPORTED


def test_classify_failure_causes():
    engine = VerdictEngine()
    assert engine.classify_failure([obs("x", "dns_rejected")]) is BlockCause.DNS_REJECTION
    assert engine.classify_failure([obs("x", "app_rejected")]) is BlockCause.APP_REJECTION
    assert engine.classify_failure([obs("x", "timeout")]) is BlockCause.TIMEOUT
    assert engine.classify_failure([obs("x", "network_failure")]) is BlockCause.NETWORK_FAILURE
