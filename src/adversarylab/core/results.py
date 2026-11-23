"""Verdict, confidence, block-cause and execution-mode model plus the verdict engine.

The engine is deliberately conservative: a missing packet is never a PASS, and a failure
is attributed to a specific cause before it can be called a firewall block.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from ..clock import Clock, SystemClock
from ..ids import new_id


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    DETECTED = "DETECTED"
    DETECTED_AND_BLOCKED = "DETECTED_AND_BLOCKED"
    NOT_DETECTED = "NOT_DETECTED"
    NOT_BLOCKED = "NOT_BLOCKED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNSUPPORTED = "UNSUPPORTED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class BlockCause(str, Enum):
    FIREWALL_CONFIRMED = "FIREWALL_CONFIRMED"
    NETWORK_FAILURE = "NETWORK_FAILURE"
    DNS_REJECTION = "DNS_REJECTION"
    APP_REJECTION = "APP_REJECTION"
    OS_REJECTION = "OS_REJECTION"
    SERVER_REJECTION = "SERVER_REJECTION"
    TIMEOUT = "TIMEOUT"
    UNKNOWN = "UNKNOWN"
    NONE = "NONE"


class ExecutionMode(str, Enum):
    REAL_NETWORK = "REAL_NETWORK"
    PROTOCOL_SIMULATION = "PROTOCOL_SIMULATION"
    VIRTUALIZED = "VIRTUALIZED"
    PASSIVE_OBSERVATION = "PASSIVE_OBSERVATION"
    PARTIAL = "PARTIAL"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True, slots=True)
class Observation:
    source: str
    kind: str
    timestamp: datetime
    summary: str
    details: Mapping[str, Any] = field(default_factory=dict)
    evidence_ref: str | None = None
    count: int | None = None

    @property
    def is_firewall_reported(self) -> bool:
        return self.source in {"firewall", EventSourceFIREWALL_SENTINEL}


# Sentinel used above without importing the enum to keep Observation dependency-light.
EventSourceFIREWALL_SENTINEL = "firewall"


@dataclass
class Assertion:
    name: str
    expected: Any
    observed: Any
    passed: bool
    note: str = ""


@dataclass
class TestResult:
    # Not a pytest test class despite the Test* prefix.
    __test__ = False

    result_id: str
    test_id: str
    scenario_id: str | None
    verdict: Verdict
    confidence: Confidence
    block_cause: BlockCause
    execution_mode: ExecutionMode
    rationale: str
    observations: list[Observation] = field(default_factory=list)
    assertions: list[Assertion] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    started_at: datetime | None = None
    ended_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "result_id": self.result_id,
            "test_id": self.test_id,
            "scenario_id": self.scenario_id,
            "verdict": self.verdict.value,
            "confidence": self.confidence.value,
            "block_cause": self.block_cause.value,
            "execution_mode": self.execution_mode.value,
            "rationale": self.rationale,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "observations": [
                {
                    "source": o.source,
                    "kind": o.kind,
                    "timestamp": o.timestamp.isoformat(),
                    "summary": o.summary,
                    "details": dict(o.details),
                    "evidence_ref": o.evidence_ref,
                }
                for o in self.observations
            ],
            "assertions": [
                {
                    "name": a.name,
                    "expected": a.expected,
                    "observed": a.observed,
                    "passed": a.passed,
                    "note": a.note,
                }
                for a in self.assertions
            ],
            "evidence_refs": list(self.evidence_refs),
            "limitations": list(self.limitations),
        }


@dataclass
class EvaluationPolicy:
    """How to interpret a set of observations for one test."""

    expect_block: bool
    require_firewall_confirmation: bool = True
    treat_timeout_as_block: bool = False
    notes: str = ""


_RESULT_KINDS = {
    "allowed",
    "blocked",
    "dns_rejected",
    "app_rejected",
    "server_rejected",
    "network_failure",
    "timeout",
    "detected",
    "firewall_block",
    "sink_hit",
}

_FIREWALL_SOURCES = {"firewall", "firewall_api", "firewall_log", "firewall_adb"}

# Observation kinds that assert the *absence* of traffic rather than an outcome.
# They are setup bookkeeping or explicit "nothing arrived" reports; none of them is
# evidence that the firewall blocked or allowed anything.
_ABSENCE_KINDS = {
    "no_observations",
    "sink_no_hit",
    "endpoint_applied",
    "lab_endpoint_applied",
    "http_endpoint_applied",
    # An explicitly disabled/opt-in-only experiment produces no outcome evidence at all.
    "opt_in_required",
    "skipped",
}


def _is_absence_kind(kind: str) -> bool:
    return kind in _ABSENCE_KINDS or kind.endswith("_applied")


class VerdictEngine:
    def __init__(self, clock: Clock | None = None) -> None:
        self.clock = clock or SystemClock()

    # ------------------------------------------------------------------
    # Cause classification
    # ------------------------------------------------------------------
    def classify_failure(self, observations: Iterable[Observation]) -> BlockCause:
        obs = list(observations)
        kinds = {o.kind for o in obs}
        sources = {o.source for o in obs}
        if "firewall_block" in kinds or "blocked" in kinds and sources & _FIREWALL_SOURCES:
            return BlockCause.FIREWALL_CONFIRMED
        if "dns_rejected" in kinds:
            return BlockCause.DNS_REJECTION
        if "app_rejected" in kinds:
            return BlockCause.APP_REJECTION
        if "server_rejected" in kinds:
            return BlockCause.SERVER_REJECTION
        if "timeout" in kinds:
            return BlockCause.TIMEOUT
        if "network_failure" in kinds:
            return BlockCause.NETWORK_FAILURE
        if "blocked" in kinds or "detected" in kinds:
            return BlockCause.UNKNOWN
        return BlockCause.NONE

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------
    def evaluate(
        self,
        *,
        test_id: str,
        scenario_id: str | None,
        observations: Iterable[Observation],
        execution_mode: ExecutionMode,
        policy: EvaluationPolicy,
        limitations: Iterable[str] = (),
        evidence_refs: Iterable[str] = (),
    ) -> TestResult:
        obs = list(observations)
        now = self.clock.now()
        started = min((o.timestamp for o in obs), default=now)
        result = TestResult(
            result_id=new_id("res"),
            test_id=test_id,
            scenario_id=scenario_id,
            verdict=Verdict.INCONCLUSIVE,
            confidence=Confidence.UNKNOWN,
            block_cause=BlockCause.NONE,
            execution_mode=execution_mode,
            rationale="",
            observations=obs,
            started_at=started,
            ended_at=now,
            limitations=list(limitations),
            evidence_refs=list(evidence_refs),
        )

        if execution_mode is ExecutionMode.UNSUPPORTED:
            result.verdict = Verdict.UNSUPPORTED
            result.rationale = "Test requires capabilities not present on this host."
            return result

        if not obs:
            result.verdict = Verdict.INCONCLUSIVE
            result.rationale = "No observations were collected; absence of evidence is not evidence of a block."
            return result

        kinds = {o.kind for o in obs}
        sources = {o.source for o in obs}
        independent_sources = {s for s in sources if s not in _FIREWALL_SOURCES}

        if policy.expect_block:
            self._evaluate_expected_block(result, kinds, sources, independent_sources, policy)
        else:
            self._evaluate_expected_allow(result, kinds, sources, independent_sources, policy)

        # Simulated/virtualized modes can never be a fully verified wireless result.
        if execution_mode in {
            ExecutionMode.PROTOCOL_SIMULATION,
            ExecutionMode.VIRTUALIZED,
            ExecutionMode.PARTIAL,
        }:
            if result.verdict in {Verdict.PASS, Verdict.BLOCKED, Verdict.DETECTED_AND_BLOCKED}:
                result.verdict = Verdict.PARTIALLY_VERIFIED
                result.confidence = min(result.confidence, Confidence.LOW, key=_conf_rank)
                result.limitations.append(
                    f"Execution mode {execution_mode.value} is not proof of real wireless resistance."
                )
        return result

    def _evaluate_expected_block(
        self,
        result: TestResult,
        kinds: set[str],
        sources: set[str],
        independent_sources: set[str],
        policy: EvaluationPolicy,
    ) -> None:
        allowed = bool(kinds & {"allowed", "sink_hit"})
        blocked = bool(kinds & {"blocked", "firewall_block"})
        detected = bool(kinds & {"detected", "firewall_block"})
        cause = self.classify_failure(result.observations)

        if allowed:
            result.verdict = Verdict.FAIL
            result.block_cause = BlockCause.NONE
            result.confidence = self._confidence(sources, independent_sources)
            result.rationale = "Traffic reached the destination; the expected block did not occur."
            return

        if blocked:
            firewall_confirmed = bool(sources & _FIREWALL_SOURCES)
            corroborated = firewall_confirmed and bool(independent_sources)
            if policy.require_firewall_confirmation and not firewall_confirmed:
                result.verdict = Verdict.INCONCLUSIVE
                result.block_cause = cause
                result.confidence = Confidence.LOW
                result.rationale = (
                    "A block was observed but no firewall-reported evidence was available; "
                    "cause cannot be confirmed as a firewall decision."
                )
                return
            if detected and blocked:
                result.verdict = Verdict.DETECTED_AND_BLOCKED
            else:
                result.verdict = Verdict.BLOCKED
            result.block_cause = cause
            result.confidence = (
                Confidence.HIGH if corroborated else Confidence.MEDIUM
            )
            result.rationale = (
                f"Block confirmed (cause={cause.value}); "
                f"corroborating sources={sorted(independent_sources) or 'none'}."
            )
            return

        # No allowed, no explicit block: distinguish timeout/failure.
        if cause in {BlockCause.TIMEOUT, BlockCause.NETWORK_FAILURE}:
            if policy.treat_timeout_as_block:
                result.verdict = Verdict.INCONCLUSIVE
                result.block_cause = cause
                result.confidence = Confidence.LOW
                result.rationale = (
                    f"Traffic did not arrive and no explicit block was seen (cause={cause.value}); "
                    "the failure cannot be attributed to the firewall."
                )
            else:
                result.verdict = Verdict.INCONCLUSIVE
                result.block_cause = cause
                result.confidence = Confidence.LOW
                result.rationale = (
                    f"No block evidence; observed failure cause={cause.value}. "
                    "A network-level failure is not a firewall block."
                )
            return

        result.verdict = Verdict.INCONCLUSIVE
        result.block_cause = cause
        result.confidence = Confidence.LOW
        result.rationale = "Insufficient evidence to classify the outcome."

    def _evaluate_expected_allow(
        self,
        result: TestResult,
        kinds: set[str],
        sources: set[str],
        independent_sources: set[str],
        policy: EvaluationPolicy,
    ) -> None:
        allowed = bool(kinds & {"allowed", "sink_hit"})
        if allowed:
            result.verdict = Verdict.PASS
            result.block_cause = BlockCause.NONE
            result.confidence = self._confidence(sources, independent_sources)
            result.rationale = "Expected-allowed traffic reached the destination."
            return

        cause = self.classify_failure(result.observations)
        if not kinds or all(_is_absence_kind(k) for k in kinds):
            # Nothing was observed at all: absence of telemetry is not evidence of
            # a block, so the control is inconclusive rather than a verdict.
            result.verdict = Verdict.INCONCLUSIVE
            result.block_cause = BlockCause.NONE
            result.confidence = Confidence.LOW
            result.rationale = (
                "Expected-allowed control traffic was not observed; missing telemetry "
                "is reported as a limitation and is not treated as a block or a pass."
            )
            return
        if cause in {BlockCause.TIMEOUT, BlockCause.NETWORK_FAILURE}:
            # The lab path itself failed; this says nothing about the firewall.
            result.verdict = Verdict.INCONCLUSIVE
            result.block_cause = cause
            result.confidence = Confidence.LOW
            result.rationale = (
                f"Expected-allowed traffic did not arrive (cause={cause.value}); the "
                "failure is a lab/network fault, not evidence of a firewall decision."
            )
            return
        result.verdict = Verdict.FAIL
        result.block_cause = cause
        result.confidence = self._confidence(sources, independent_sources)
        result.rationale = (
            f"Expected-allowed traffic did not reach the destination "
            f"(cause={cause.value}); this may be a false positive."
        )

    @staticmethod
    def _confidence(sources: set[str], independent_sources: set[str]) -> Confidence:
        if len(independent_sources) >= 2:
            return Confidence.HIGH
        if independent_sources:
            return Confidence.MEDIUM
        if sources:
            return Confidence.LOW
        return Confidence.UNKNOWN


def _conf_rank(c: Confidence) -> int:
    return {Confidence.UNKNOWN: 0, Confidence.LOW: 1, Confidence.MEDIUM: 2, Confidence.HIGH: 3}[c]
