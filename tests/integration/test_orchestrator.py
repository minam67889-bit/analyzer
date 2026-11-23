from __future__ import annotations

from adversarylab.adversary.actions import FakeActionRunner
from adversarylab.adversary.orchestrator import Orchestrator, OrchestratorState
from adversarylab.config.schema import default_config
from adversarylab.core.events import EventCategory, EventSeverity, EventSource, make_event
from adversarylab.core.results import Verdict
from adversarylab.tests.catalog import build_default_registry


def _orchestrator(tmp_path, bus, db, capabilities, config=None) -> Orchestrator:
    config = config or default_config()
    config.tests.observation_window_seconds = 0.05
    return Orchestrator(
        config=config,
        registry=build_default_registry(),
        capabilities=capabilities,
        bus=bus,
        db=db,
        evidence_root=tmp_path / "evidence",
        action_runner=FakeActionRunner(),
        clock=None,
    )


def test_session_prepare_plan_and_run(tmp_path, bus, db, all_capabilities, clock):
    orchestrator = _orchestrator(tmp_path, bus, db, all_capabilities)
    orchestrator.clock = clock
    session_id = orchestrator.create_session()
    assert session_id
    prep = orchestrator.prepare()
    assert prep.ok, prep.problems
    assert orchestrator.state.state is OrchestratorState.READY

    plan = orchestrator.plan()
    assert plan.selected
    assert plan.unsupported == []

    result = orchestrator.run_test("DNS-SPOOF-A")
    assert result.test_id == "DNS-SPOOF-A"
    # No device/capture traffic: the honest outcome is INCONCLUSIVE.
    assert result.verdict is Verdict.INCONCLUSIVE

    manifest = orchestrator.finalize()
    assert manifest is not None and manifest[0].exists()


def test_run_test_with_firewall_block_evidence(tmp_path, bus, db, all_capabilities, clock):
    orchestrator = _orchestrator(tmp_path, bus, db, all_capabilities)
    orchestrator.clock = clock
    orchestrator.create_session()
    orchestrator.prepare()
    bus.publish(make_event(
        session_id=orchestrator.session_id,
        test_id="DNS-SPOOF-A",
        category=EventCategory.FIREWALL,
        source=EventSource.FIREWALL,
        severity=EventSeverity.ALERT,
        summary="firewall blocked connection",
        details={"action": "block", "dst": "10.10.0.250"},
        clock=clock,
    ))
    result = orchestrator.run_test("DNS-SPOOF-A")
    assert result.verdict is Verdict.DETECTED_AND_BLOCKED
    assert result.block_cause.value == "FIREWALL_CONFIRMED"


def test_run_test_with_syn_evidence_is_inconclusive(tmp_path, bus, db, all_capabilities, clock):
    orchestrator = _orchestrator(tmp_path, bus, db, all_capabilities)
    orchestrator.clock = clock
    orchestrator.create_session()
    orchestrator.prepare()
    bus.publish(make_event(
        session_id=orchestrator.session_id,
        test_id="DNS-SPOOF-A",
        category=EventCategory.CONNECTION,
        source=EventSource.PACKET_CAPTURE,
        severity=EventSeverity.INFO,
        summary="SYN to spoofed destination",
        dst_addr="10.10.0.250",
        details={"tcp_flags": ["SYN"]},
        clock=clock,
    ))
    result = orchestrator.run_test("DNS-SPOOF-A")
    assert result.verdict is Verdict.INCONCLUSIVE


def test_full_assessment_completes(tmp_path, bus, db, all_capabilities, clock):
    orchestrator = _orchestrator(tmp_path, bus, db, all_capabilities)
    orchestrator.clock = clock
    orchestrator.create_session()
    orchestrator.prepare()
    result = orchestrator.run_assessment()
    assert result.status == "completed"
    assert len(result.results) == len(result.plan.selected)
    assert result.recovery is not None
    assert orchestrator.state.state is OrchestratorState.STOPPED


def test_emergency_stop(tmp_path, bus, db, all_capabilities, clock):
    orchestrator = _orchestrator(tmp_path, bus, db, all_capabilities)
    orchestrator.clock = clock
    orchestrator.create_session()
    orchestrator.prepare()
    orchestrator.emergency_stop()
    assert orchestrator.state.state is OrchestratorState.EMERGENCY


def test_planner_marks_unsupported(tmp_path, bus, db, clock):
    from adversarylab.adversary.planner import AssessmentPlanner
    from adversarylab.core.capability import CapabilitySet

    caps = CapabilitySet()  # nothing available
    registry = build_default_registry()
    plan = AssessmentPlanner(registry, caps).plan("s")
    assert plan.selected == []
    assert plan.unsupported
