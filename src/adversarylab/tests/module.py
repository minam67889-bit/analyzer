"""Test module base class and execution runner."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..clock import Clock, SystemClock
from ..core.bus import EventFilter
from ..core.capability import CapabilitySet
from ..core.results import (
    BlockCause,
    Confidence,
    EvaluationPolicy,
    Observation,
    TestResult,
    Verdict,
    VerdictEngine,
)
from ..evidence.store import EvidenceStore
from ..inventory.discovery import DestinationInventory
from ..logging_config import get_logger
from .spec import TestSpec


class TestContext:
    """Everything a test module may use, injected by the orchestrator."""

    def __init__(
        self,
        *,
        session_id: str,
        scenario_id: str | None = None,
        config: Any | None = None,
        capabilities: CapabilitySet | None = None,
        bus: Any | None = None,
        db: Any | None = None,
        evidence: EvidenceStore | None = None,
        inventory: DestinationInventory | None = None,
        clock: Clock | None = None,
        device: Any | None = None,
        lab: Any | None = None,
        action_runner: Any | None = None,
        cancel_token: Any | None = None,
        params: dict[str, Any] | None = None,
        cookie_ground_truth: Any | None = None,
        reveal_cookie_values: bool = False,
    ) -> None:
        self.session_id = session_id
        self.scenario_id = scenario_id
        self.config = config
        self.capabilities = capabilities
        self.bus = bus
        self.db = db
        self.evidence = evidence
        self.inventory = inventory
        self.clock = clock or SystemClock()
        self.device = device
        self.lab = lab
        self.action_runner = action_runner
        self.cancel_token = cancel_token
        # Laboratory cookie ground truth: what the lab knows it issued, kept separate
        # from anything the attacker side can observe.
        self.cookie_ground_truth = cookie_ground_truth
        self.reveal_cookie_values = reveal_cookie_values
        self.params = dict(params or {})
        self.logger = get_logger(f"adversarylab.test.{self.__class__.__name__}")
        self.collected: list[Observation] = []
        self.started_at = None
        self.ended_at = None
        self.test_id: str | None = None

    def param(self, name: str, default: Any = None) -> Any:
        return self.params.get(name, default)

    def observe(self, observation: Observation) -> None:
        self.collected.append(observation)

    def record_evidence(self, data: bytes, *, kind: str, name: str, sub: str = "logs",
                        metadata: dict | None = None):
        if self.evidence is None:
            return None
        return self.evidence.record_bytes(
            data, kind=kind, name=name, sub=sub,
            test_id=self._test_id(), scenario_id=self.scenario_id, metadata=metadata,
        )

    def _test_id(self) -> str | None:
        module = getattr(self, "_module", None)
        return module.spec.id if module else None


class TestModule(ABC):
    """Base class for all adversarial tests.

    Implement ``execute`` (apply the adversarial condition) and ``collect`` (gather
    observations). ``evaluate`` defaults to the verdict engine using the spec's policy.
    """

    spec: TestSpec

    def __init__(self, ctx: TestContext) -> None:
        self.ctx = ctx
        ctx._module = self  # type: ignore[attr-defined]

    # Hooks -----------------------------------------------------------------
    def setup(self) -> None:
        return None

    @abstractmethod
    def execute(self) -> None:
        raise NotImplementedError

    def collect(self) -> list[Observation]:
        return collect_observations(self.ctx)

    def teardown(self) -> None:
        return None

    def evaluate(self, observations: list[Observation]) -> TestResult:
        engine = VerdictEngine(clock=self.ctx.clock)
        policy = EvaluationPolicy(
            expect_block=self.spec.expect_block,
            require_firewall_confirmation=self.spec.require_firewall_confirmation,
            treat_timeout_as_block=self.spec.treat_timeout_as_block,
        )
        evidence_refs = [
            r.evidence_id for r in (self.ctx.evidence.records_for(self.spec.id, self.ctx.scenario_id)
                                    if self.ctx.evidence else [])
        ]
        result = engine.evaluate(
            test_id=self.spec.id,
            scenario_id=self.ctx.scenario_id,
            observations=observations,
            execution_mode=self.spec.execution_mode,
            policy=policy,
            limitations=self.spec.known_limitations,
            evidence_refs=evidence_refs,
        )
        return result


class TestRunner:
    """Executes one test module with observation window, teardown and evidence capture."""

    def __init__(self, *, observation_window: float = 6.0, clock: Clock | None = None) -> None:
        self.observation_window = observation_window
        self.clock = clock or SystemClock()

    def run(self, module: TestModule) -> TestResult:
        ctx = module.ctx
        ctx.test_id = module.spec.id
        started = self.clock.now()
        ctx.started_at = started
        result: TestResult | None = None
        module.setup()
        try:
            module.execute()
            self._sleep(self.observation_window, ctx)
            ctx.ended_at = self.clock.now()
            observations = module.collect()
            result = module.evaluate(observations)
        finally:
            try:
                module.teardown()
            except Exception as exc:  # teardown failure must not hide the result
                ctx.logger.exception("test teardown failed")
                if result is not None and "teardown failures" not in result.limitations:
                    result.limitations.append(f"teardown failure: {exc}")
        assert result is not None
        # Experiments that require an explicit operator opt-in (for example installing a
        # laboratory CA) are UNSUPPORTED when that opt-in is off — never a silent pass
        # and never a failure of the firewall.
        if module.spec.requires_user_confirmation:
            tests_config = getattr(ctx.config, "tests", None)
            allowed = bool(getattr(tests_config, "allow_certificate_install_opt_in", False))
            if not allowed:
                result.verdict = Verdict.UNSUPPORTED
                result.block_cause = BlockCause.NONE
                result.confidence = Confidence.UNKNOWN
                result.rationale = (
                    "Experiment requires an explicit operator opt-in "
                    "(tests.allow_certificate_install_opt_in); it was not enabled, so no "
                    "device change was attempted and no outcome evidence exists."
                )
                result.limitations.append("skipped: operator opt-in not enabled")
        result.started_at = started
        result.ended_at = self.clock.now()
        self._capture(module, result)
        return result

    def _sleep(self, seconds: float, ctx: TestContext) -> None:
        import time

        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if getattr(ctx, "cancel_token", None) is not None:
                ctx.cancel_token.raise_if_cancelled()
            time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))

    def _capture(self, module: TestModule, result: TestResult) -> None:
        if ctx := module.ctx:
            if ctx.evidence is not None:
                ctx.evidence.record_text(
                    _result_text(result),
                    kind="test_result",
                    name=f"{module.spec.id}-{result.result_id}.json",
                    sub="logs",
                    test_id=module.spec.id,
                    scenario_id=ctx.scenario_id,
                    metadata={"verdict": result.verdict.value, "confidence": result.confidence.value},
                )


def collect_observations(ctx: TestContext) -> list[Observation]:
    """Merge explicit observations with bus events inside the test's time window."""
    observations: list[Observation] = list(ctx.collected)
    seen = {(o.source, o.kind, o.timestamp, o.summary) for o in observations}
    if ctx.bus is not None:
        for event in ctx.bus.history(EventFilter(session_id=ctx.session_id)):
            tagged = ctx.test_id is not None and event.test_id == ctx.test_id
            in_window = True
            if ctx.started_at is not None and event.timestamp < ctx.started_at:
                in_window = False
            if ctx.ended_at is not None and event.timestamp > ctx.ended_at:
                in_window = False
            if not (tagged or in_window):
                continue
            key = (event.source.value, event.category.value, event.timestamp, event.summary)
            if key in seen:
                continue
            seen.add(key)
            observations.append(
                Observation(
                    source=event.source.value,
                    kind=event.category.value,
                    timestamp=event.timestamp,
                    summary=event.summary,
                    details=dict(event.details),
                    evidence_ref=event.evidence_ref,
                )
            )
    return observations


def _result_text(result: TestResult) -> str:
    import json

    return json.dumps(result.to_dict(), indent=2, sort_keys=True)
