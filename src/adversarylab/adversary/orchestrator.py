"""Central test orchestrator.

Owns the session lifecycle: capability validation, preparation, planning, execution,
correlation, recovery and reporting. Pause/resume/stop/emergency are explicit states.
"""

from __future__ import annotations

import platform as _platform
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from .. import __version__
from ..clock import Clock, SystemClock
from ..cookies.ground_truth import CookieGroundTruth
from ..core.cancellation import CancellationToken
from ..core.capability import Capability, CapabilitySet
from ..core.context import test_context
from ..core.events import NetworkEvent
from ..core.results import TestResult, Verdict
from ..core.state import StateMachine, TransitionError
from ..errors import OrchestratorError
from ..evidence.store import EvidenceStore
from ..ids import new_session_id
from ..inventory.discovery import DestinationInventory, DiscoveryEngine
from ..inventory.ownership import OwnershipPolicy
from ..logging_config import get_logger
from ..tests.module import TestContext, TestRunner
from ..tests.registry import CoverageRow, TestRegistry
from .planner import AssessmentPlan, AssessmentPlanner
from .profiles import ProfileLibrary
from .recovery import RecoveryManager, RecoveryReport
from .scenarios import Scenario, ScenarioLibrary, ScenarioRunner

logger = get_logger(__name__)


class OrchestratorState(str, Enum):
    IDLE = "idle"
    PREPARING = "preparing"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    RECOVERING = "recovering"
    STOPPED = "stopped"
    EMERGENCY = "emergency"


_TRANSITIONS = {
    OrchestratorState.IDLE: {OrchestratorState.PREPARING, OrchestratorState.STOPPED,
                             OrchestratorState.EMERGENCY},
    OrchestratorState.PREPARING: {OrchestratorState.READY, OrchestratorState.STOPPED,
                                  OrchestratorState.EMERGENCY},
    OrchestratorState.READY: {OrchestratorState.RUNNING, OrchestratorState.PAUSED,
                              OrchestratorState.RECOVERING, OrchestratorState.STOPPED,
                              OrchestratorState.EMERGENCY},
    OrchestratorState.RUNNING: {OrchestratorState.READY, OrchestratorState.PAUSED,
                                OrchestratorState.RECOVERING, OrchestratorState.STOPPED,
                                OrchestratorState.EMERGENCY},
    OrchestratorState.PAUSED: {OrchestratorState.RUNNING, OrchestratorState.RECOVERING,
                               OrchestratorState.STOPPED, OrchestratorState.EMERGENCY},
    OrchestratorState.RECOVERING: {OrchestratorState.STOPPED, OrchestratorState.READY,
                                   OrchestratorState.EMERGENCY},
    OrchestratorState.STOPPED: {OrchestratorState.IDLE, OrchestratorState.EMERGENCY},
    OrchestratorState.EMERGENCY: {OrchestratorState.IDLE},
}


@dataclass
class PreparationReport:
    ok: bool
    capability_set: dict
    infrastructure: dict
    device: dict
    isolation: dict
    inventory_count: int
    problems: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "capabilities": self.capability_set,
            "infrastructure": self.infrastructure,
            "device": self.device,
            "isolation": self.isolation,
            "inventory_count": self.inventory_count,
            "problems": list(self.problems),
        }


def _iso(value: Any) -> str | None:
    """Serialize a datetime, tolerating an already-serialized ISO string."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


@dataclass
class AssessmentResult:
    session_id: str
    status: str
    started_at: datetime
    finished_at: datetime | None = None
    plan: AssessmentPlan | None = None
    results: list[TestResult] = field(default_factory=list)
    coverage: list[CoverageRow] = field(default_factory=list)
    recovery: RecoveryReport | None = None
    campaigns: list[dict[str, Any]] = field(default_factory=list)
    cookie_exposure: dict[str, Any] = field(default_factory=dict)
    longitudinal: dict[str, Any] = field(default_factory=dict)
    environment: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "status": self.status,
            "started_at": _iso(self.started_at),
            "finished_at": _iso(self.finished_at),
            "plan": self.plan.to_dict() if self.plan else None,
            "results": [r.to_dict() for r in self.results],
            "coverage": [c.to_dict() for c in self.coverage],
            "recovery": self.recovery.to_dict() if self.recovery else None,
            "campaigns": [dict(c) for c in self.campaigns],
            "cookie_exposure": dict(self.cookie_exposure),
            "longitudinal": dict(self.longitudinal),
            "environment": self.environment,
        }


class Orchestrator:
    def __init__(
        self,
        *,
        config: Any,
        registry: TestRegistry,
        capabilities: CapabilitySet,
        bus: Any,
        db: Any,
        evidence_root: str | Path,
        action_runner: Any,
        clock: Clock | None = None,
        cancel_token: CancellationToken | None = None,
        device: Any | None = None,
        lab: Any | None = None,
        capture: Any | None = None,
        profiles: ProfileLibrary | None = None,
        scenarios: ScenarioLibrary | None = None,
    ) -> None:
        self.config = config
        self.registry = registry
        self.capabilities = capabilities
        self.bus = bus
        self.db = db
        self.evidence_root = Path(evidence_root)
        self.action_runner = action_runner
        self.clock = clock or SystemClock()
        self.cancel_token = cancel_token or CancellationToken()
        self.device = device
        self.lab = lab
        self.capture = capture
        self.profiles = profiles or ProfileLibrary()
        self.scenarios = scenarios or ScenarioLibrary()
        self.state = StateMachine(OrchestratorState.IDLE, _TRANSITIONS)
        self.session_id: str | None = None
        self.evidence: EvidenceStore | None = None
        self.inventory: DestinationInventory | None = None
        self.discovery: DiscoveryEngine | None = None
        self.cookie_ground_truth: CookieGroundTruth | None = None
        self.recovery = RecoveryManager(clock=self.clock)
        self._paused = False
        self._planned: AssessmentPlan | None = None
        self._last_result: AssessmentResult | None = None
        self._bus_sink = self._on_event
        self.bus.subscribe(self._bus_sink)

    # ------------------------------------------------------------------
    # Session
    # ------------------------------------------------------------------
    def create_session(self, *, prefix: str = "sess") -> str:
        self.session_id = new_session_id(prefix)
        self.evidence = EvidenceStore(self.evidence_root, self.session_id, clock=self.clock, db=self.db)
        self.inventory = DestinationInventory(
            self.session_id,
            OwnershipPolicy(self.config.scope),
            clock=self.clock,
        )
        self.discovery = DiscoveryEngine(self.inventory, db=self.db, bus=self.bus)
        # Laboratory ground truth for synthetic cookies, kept per session and separate
        # from every attacker-side observation.
        self.cookie_ground_truth = CookieGroundTruth(
            Path(self.evidence_root) / self.session_id / "cookie_ground_truth.db",
            clock=self.clock,
        )
        # Keep any service-backed runner's event attribution in sync with this session.
        self._sync_runner_context()
        self.evidence.create_session(
            config=_config_dict(self.config),
            environment=self.environment_fingerprint(),
        )
        return self.session_id

    def environment_fingerprint(self) -> dict:
        return {
            "tool_version": __version__,
            "platform": _platform.platform(),
            "system": _platform.system(),
            "release": _platform.release(),
            "machine": _platform.machine(),
            "python": sys.version.split()[0],
            "hostname": _platform.node(),
            "timestamp": self.clock.now().isoformat(),
            "config_path": str(getattr(self.config, "_source_path", "") or ""),
        }

    # ------------------------------------------------------------------
    # Preparation
    # ------------------------------------------------------------------
    def prepare(self) -> PreparationReport:
        self._transition(OrchestratorState.PREPARING)
        problems: list[str] = []
        if self.session_id is None:
            self.create_session()
        assert self.session_id is not None and self.evidence is not None

        try:
            self.capabilities.require(Capability.PACKET_CAPTURE, Capability.IPV4)
        except Exception as exc:
            problems.append(str(exc))

        infra: dict = {"backend": None, "status": "not-configured"}
        if self.lab is not None:
            try:
                status = self.lab.start(self.config.infrastructure)
                infra = {"backend": getattr(self.lab, "name", type(self.lab).__name__),
                         "status": status.state.value if hasattr(status, "state") else str(status),
                         "details": getattr(status, "details", {})}
            except Exception as exc:
                problems.append(f"infrastructure start failed: {exc}")
                infra = {"backend": getattr(self.lab, "name", type(self.lab).__name__),
                         "status": "failed", "error": str(exc)}

        device_info: dict = {"available": self.device is not None}
        if self.device is not None:
            try:
                device_info = self.device.device_info()
            except Exception as exc:
                problems.append(f"device validation failed: {exc}")
                device_info = {"available": False, "error": str(exc)}

        isolation = {"verified": False}
        if self.config.assessment.verify_isolation:
            isolation = self._verify_isolation()

        self.recovery.register("action_runner", self.action_runner.revert_all,
                               lambda: self.action_runner.status().get("applied_actions", []) == [])
        self._transition(OrchestratorState.READY)
        report = PreparationReport(
            ok=not problems,
            capability_set=self.capabilities.to_dict(),
            infrastructure=infra,
            device=device_info,
            isolation=isolation,
            inventory_count=len(self.inventory.all()) if self.inventory else 0,
            problems=problems,
        )
        self.evidence.record_text(
            _json(report.to_dict()), kind="preparation", name="preparation.json", sub="logs"
        )
        return report

    def _verify_isolation(self) -> dict:
        allowed = [str(net) for net in getattr(self.config.scope, "ip_ranges", [])]
        return {
            "verified": bool(allowed),
            "deny_egress_by_default": bool(self.config.scope.deny_egress_by_default),
            "allowed_lab_ranges": allowed,
            "method": "configuration assertion; live egress probe is part of the assessment",
        }

    # ------------------------------------------------------------------
    # Planning
    # ------------------------------------------------------------------
    def plan(self) -> AssessmentPlan:
        if self.session_id is None:
            self.create_session()
        planner = AssessmentPlanner(
            self.registry,
            self.capabilities,
            include_categories=self.config.tests.include_categories,
            exclude_test_ids=self.config.tests.exclude_test_ids,
            auto_select=self.config.tests.auto_select,
        )
        self._planned = planner.plan(self.session_id)
        return self._planned

    # ------------------------------------------------------------------
    # Context factory
    # ------------------------------------------------------------------
    def _sync_runner_context(self, test_id: str | None = None,
                            scenario_id: str | None = None) -> None:
        """Propagate session/test/scenario correlation ids to the action runner."""
        runner = self.action_runner
        if runner is None:
            return
        for attribute, value in (
            ("session_id", self.session_id),
            ("test_id", test_id),
            ("scenario_id", scenario_id),
            ("evidence", self.evidence),
        ):
            if hasattr(runner, attribute):
                try:
                    setattr(runner, attribute, value)
                except Exception:
                    logger.debug("action runner rejected %s", attribute)

    def _make_context(self, test_id: str, scenario_id: str | None = None) -> TestContext:
        if self.session_id is None or self.evidence is None or self.inventory is None:
            raise OrchestratorError("no active session; call create_session()/prepare() first")
        return TestContext(
            session_id=self.session_id,
            scenario_id=scenario_id,
            config=self.config,
            capabilities=self.capabilities,
            bus=self.bus,
            db=self.db,
            evidence=self.evidence,
            inventory=self.inventory,
            clock=self.clock,
            device=self.device,
            lab=self.lab,
            action_runner=self.action_runner,
            cancel_token=self.cancel_token,
            params={},
            cookie_ground_truth=self.cookie_ground_truth,
            reveal_cookie_values=bool(
                getattr(self.config.tests, "reveal_cookie_values", False)
            ),
        )

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------
    def run_test(
        self,
        test_id: str,
        *,
        scenario_id: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> TestResult:
        running = self.state.state is OrchestratorState.RUNNING
        if not running:
            self._transition(OrchestratorState.RUNNING)
        # Standalone tests are independent: adversary state from a previous test is
        # reverted so a listener left bound by an earlier test cannot break this one.
        # Scenario steps deliberately share state and do not pass through here.
        if scenario_id is None:
            try:
                self.action_runner.revert_all()
            except Exception:
                logger.exception("failed to revert adversary state before %s", test_id)
        self._sync_runner_context(test_id, scenario_id)
        ctx = self._make_context(test_id, scenario_id)
        ctx.params = dict(params or {})
        module = self.registry.instantiate(test_id, ctx)
        with test_context(test_id, scenario_id):
            result = TestRunner(
                observation_window=self.config.tests.observation_window_seconds,
                clock=self.clock,
            ).run(module)
        self._store_result(result)
        if not running:
            self._transition(OrchestratorState.READY)
        return result

    def run_campaign(self, campaign: Any) -> Any:
        """Execute a multi-stage campaign, preserving observations between stages."""
        from .campaigns import CampaignRunner

        running = self.state.state is OrchestratorState.RUNNING
        if not running:
            self._transition(OrchestratorState.RUNNING)
        # Campaigns are independent of each other: state is reverted before a campaign
        # starts, but preserved between that campaign's own stages.
        try:
            self.action_runner.revert_all()
        except Exception:
            logger.exception("failed to revert adversary state before campaign %s", campaign.id)
        runner = CampaignRunner(self)
        run = runner.run(campaign, session_id=self.session_id or "")
        if self.evidence is not None:
            self.evidence.record_text(
                _json(run.to_dict()), kind="campaign", name=f"campaign-{campaign.id}.json",
                sub="report", metadata={"campaign_id": campaign.id},
            )
        if not running:
            self._transition(OrchestratorState.READY)
        return run

    def _run_campaigns(self, plan: AssessmentPlan,
                       results: list[TestResult]) -> list[dict[str, Any]]:
        """Run selected predefined campaigns and optionally one dynamic campaign."""
        from .campaigns import CampaignLibrary, DynamicCampaignBuilder

        library = CampaignLibrary()
        runs: list[dict[str, Any]] = []
        selected = [
            library.get(cid) for cid in self.config.assessment.campaign_ids if library.get(cid)
        ] or library.all()
        for campaign in selected:
            runs.append(self.run_campaign(campaign).to_dict())
        if self.config.assessment.allow_dynamic_campaigns:
            builder = DynamicCampaignBuilder(self.registry)
            domains = sorted({d.host for d in (self.inventory.all() if self.inventory else [])
                              if d.host})
            plaintext = any(
                r.verdict is Verdict.PASS and r.test_id.startswith(("HTTP", "COOKIE"))
                for r in results
            )
            tls = any(r.test_id.startswith("TLS-") for r in results)
            dynamic = builder.build(
                discovered_domains=domains,
                lab_reachable=bool(plan.selected),
                plaintext_http_observed=plaintext,
                tls_observed=tls,
            )
            runs.append(self.run_campaign(dynamic).to_dict())
        return runs

    def run_scenario(self, scenario: Scenario) -> list[TestResult]:
        self._transition(OrchestratorState.RUNNING)
        runner = ScenarioRunner(
            registry=self.registry,
            context_factory=self._make_context,
            cancel_token=self.cancel_token,
            observation_window=self.config.tests.observation_window_seconds,
        )
        results: list[TestResult] = []
        with test_context(None, scenario.id):
            for step in scenario.steps:
                self._check_pause()
                self.cancel_token.raise_if_cancelled()
                self._sync_runner_context(step.test_id, scenario.id)
                ctx = self._make_context(step.test_id, scenario.id)
                ctx.params = dict(step.params)
                module = self.registry.instantiate(step.test_id, ctx)
                with test_context(step.test_id, scenario.id):
                    result = runner.runner.run(module)
                self._store_result(result)
                results.append(result)
                if result.verdict.value == "FAIL" and not step.continue_on_failure:
                    break
        self._transition(OrchestratorState.READY)
        return results

    def run_assessment(self) -> AssessmentResult:
        self._transition(OrchestratorState.RUNNING)
        if self.session_id is None:
            self.create_session()
        plan = self._planned or self.plan()
        result = AssessmentResult(
            session_id=self.session_id,
            status="running",
            started_at=self.clock.now(),
            plan=plan,
            environment=self.environment_fingerprint(),
        )
        try:
            for test_id in plan.selected:
                self._check_pause()
                self.cancel_token.raise_if_cancelled()
                for attempt in range(int(self.config.tests.repeat_count)):
                    test_result = self.run_test(test_id, params={"attempt": attempt})
                    result.results.append(test_result)
                    self._update_coverage(test_result, plan)
        except Exception:
            logger.exception("assessment aborted")
            result.status = "aborted"
            result.finished_at = self.clock.now()
            self._last_result = result
            self.recover()
            raise
        if self.config.assessment.run_campaigns:
            result.campaigns = self._run_campaigns(plan, result.results)
        self._analyse(result)
        result.status = "completed"
        result.finished_at = self.clock.now()
        result.coverage = plan.coverage
        self._last_result = result
        if self.config.assessment.run_recovery_checks:
            self.recover()
            result.recovery = self._last_recovery
        self._transition(OrchestratorState.STOPPED)
        self._write_assessment(result)
        return result

    def _analyse(self, result: AssessmentResult) -> None:
        """Cookie exposure + longitudinal correlation across the whole assessment."""
        events: list[NetworkEvent] = []
        if self.bus is not None:
            try:
                events = self.bus.history()
            except Exception:
                logger.exception("event history unavailable for analysis")

        if self.cookie_ground_truth is not None:
            try:
                from ..cookies.engine import CookieExposureEngine

                engine = CookieExposureEngine(
                    self.cookie_ground_truth,
                    interception_enabled=bool(
                        getattr(self.config.tests, "allow_certificate_install_opt_in", False)
                    ),
                    clock=self.clock,
                )
                engine.ingest_events(events)
                observations = engine.finalize()
                result.cookie_exposure = {
                    "summary": engine.summary(),
                    "observations": [
                        o.redacted_dict(reveal_values=bool(
                            getattr(self.config.tests, "reveal_cookie_values", False)
                        ))
                        for o in observations
                    ],
                }
                if self.evidence is not None:
                    self.evidence.record_text(
                        _json(result.cookie_exposure), kind="cookie_exposure",
                        name="cookie_exposure.json", sub="report",
                    )
            except Exception:
                logger.exception("cookie exposure analysis failed")

        try:
            from ..analysis.longitudinal import LongitudinalAnalyzer

            analyzer = LongitudinalAnalyzer(clock=self.clock)
            analyzer.ingest(events)
            result.longitudinal = analyzer.to_dict()
            if self.evidence is not None:
                self.evidence.record_text(
                    _json(result.longitudinal), kind="longitudinal",
                    name="longitudinal_analysis.json", sub="report",
                )
        except Exception:
            logger.exception("longitudinal analysis failed")

    # ------------------------------------------------------------------
    # Control
    # ------------------------------------------------------------------
    def pause(self) -> None:
        if self.state.state is OrchestratorState.RUNNING:
            self._paused = True
            self._transition(OrchestratorState.PAUSED)

    def resume(self) -> None:
        if self.state.state is OrchestratorState.PAUSED:
            self._paused = False
            self._transition(OrchestratorState.RUNNING)

    def stop(self) -> None:
        self.cancel_token.cancel()
        self.recover()
        self._transition(OrchestratorState.STOPPED)

    def emergency_stop(self) -> None:
        logger.critical("EMERGENCY STOP engaged")
        self.cancel_token.cancel()
        try:
            self.action_runner.revert_all()
        except Exception:
            logger.exception("action revert failed during emergency stop")
        self._last_recovery = self.recovery.recover_all()
        if self.lab is not None:
            try:
                self.lab.stop()
            except Exception:
                logger.exception("infrastructure stop failed during emergency stop")
        self._transition(OrchestratorState.EMERGENCY)

    def recover(self) -> RecoveryReport:
        self._transition(OrchestratorState.RECOVERING)
        self._last_recovery = self.recovery.recover_all()
        self._transition(OrchestratorState.STOPPED)
        return self._last_recovery

    _last_recovery: RecoveryReport | None = None

    # ------------------------------------------------------------------
    # Capture integration
    # ------------------------------------------------------------------
    def capture_sink(self, raw: bytes, *, linktype: int = 1) -> list[NetworkEvent]:
        """Parse a raw frame and publish normalized events with correlation ids."""
        from dataclasses import replace

        from ..capture.parsers import PacketEventParser
        from ..core.context import get_current_scenario, get_current_test

        parser = PacketEventParser(session_id=self.session_id or "")
        events = parser.parse_bytes(raw, linktype=linktype, timestamp=self.clock.now())
        for event in events:
            event = replace(
                event,
                session_id=self.session_id or event.session_id,
                test_id=event.test_id or get_current_test(),
                scenario_id=event.scenario_id or get_current_scenario(),
            )
            self.bus.publish(event)
        return events

    # ------------------------------------------------------------------
    # Persistence / reporting
    # ------------------------------------------------------------------
    def _on_event(self, event: NetworkEvent) -> None:
        if self.db is not None:
            try:
                self.db.insert_event(event)
            except Exception:
                logger.exception("failed to persist event")

    def _store_result(self, result: TestResult) -> None:
        if self.db is not None:
            self.db.insert_result(self.session_id or "", result.to_dict())
        for row in self.registry.specs():
            if row.id == result.test_id:
                break

    def _update_coverage(self, result: TestResult, plan: AssessmentPlan) -> None:
        for row in plan.coverage:
            if row.test_id != result.test_id:
                continue
            row.status = "EXECUTED"
            row.verdict = result.verdict.value
            row.confidence = result.confidence.value
            row.reason = result.rationale
            if self.db is not None:
                self.db.upsert_coverage(
                    self.session_id or "", row.test_id, row.status,
                    f"{row.verdict}:{row.confidence}",
                )

    def _write_assessment(self, result: AssessmentResult) -> None:
        if self.evidence is not None:
            self.evidence.record_text(
                _json(result.to_dict()), kind="assessment", name="assessment.json", sub="report"
            )

    def finalize(self) -> tuple[Path, str] | None:
        if self.evidence is None:
            return None
        ok, problems = self.evidence.verify()
        if problems:
            logger.error("evidence verification problems: %s", problems)
        return self.evidence.finalize()

    # ------------------------------------------------------------------
    def _transition(self, to: OrchestratorState) -> None:
        try:
            self.state.transition(to)
        except TransitionError:
            # Idempotent transitions are fine; illegal ones are surfaced.
            if self.state.state != to:
                raise

    def _check_pause(self) -> None:
        import time

        while self._paused:
            self.cancel_token.raise_if_cancelled()
            time.sleep(0.2)


def _json(payload: Any) -> str:
    import json

    return json.dumps(payload, indent=2, sort_keys=True, default=str)


def _config_dict(config: Any) -> dict:
    from dataclasses import asdict

    try:
        return asdict(config)
    except Exception:
        return {"raw": str(config)}
