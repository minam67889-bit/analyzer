from __future__ import annotations

from adversarylab.adversary.orchestrator import Orchestrator, OrchestratorState
from adversarylab.adversary.scenarios import ScenarioLibrary
from adversarylab.config.schema import default_config
from adversarylab.tests.catalog import build_default_registry


def _orchestrator(tmp_path, bus, db, capabilities, clock) -> Orchestrator:
    config = default_config()
    config.tests.observation_window_seconds = 0.05
    orch = Orchestrator(
        config=config,
        registry=build_default_registry(),
        capabilities=capabilities,
        bus=bus,
        db=db,
        evidence_root=tmp_path / "evidence",
        action_runner=__import__("adversarylab.adversary.actions", fromlist=["FakeActionRunner"]).FakeActionRunner(),
        clock=clock,
    )
    return orch


def test_scenario_library_definitions():
    library = ScenarioLibrary()
    scenarios = library.all()
    assert scenarios
    ids = {s.id for s in scenarios}
    assert "dns-manipulation" in ids
    registry = build_default_registry()
    known = {spec.id for spec in registry.specs()}
    for scenario in scenarios:
        for step in scenario.steps:
            assert step.test_id in known, f"{scenario.id} references unknown {step.test_id}"


def test_run_scenario_executes_each_step(tmp_path, bus, db, all_capabilities, clock):
    orchestrator = _orchestrator(tmp_path, bus, db, all_capabilities, clock)
    orchestrator.create_session()
    orchestrator.prepare()
    scenario = ScenarioLibrary().get("dns-manipulation")
    results = orchestrator.run_scenario(scenario)
    assert [r.test_id for r in results] == [s.test_id for s in scenario.steps]
    assert orchestrator.state.state is OrchestratorState.READY


def test_pause_is_noop_when_idle(tmp_path, bus, db, all_capabilities, clock):
    """Pause only suspends a running execution; an idle orchestrator is unchanged."""
    orchestrator = _orchestrator(tmp_path, bus, db, all_capabilities, clock)
    orchestrator.create_session()
    orchestrator.prepare()
    orchestrator.pause()
    assert orchestrator.state.state is OrchestratorState.READY


def test_pause_resume_during_scenario(tmp_path, bus, db, all_capabilities, clock):
    import threading
    import time

    orchestrator = _orchestrator(tmp_path, bus, db, all_capabilities, clock)
    orchestrator.config.tests.observation_window_seconds = 1.0
    orchestrator.create_session()
    orchestrator.prepare()
    scenario = ScenarioLibrary().get("dns-manipulation")
    outcomes: dict[str, object] = {}

    def run() -> None:
        outcomes["results"] = orchestrator.run_scenario(scenario)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    deadline = time.time() + 5
    while orchestrator.state.state is not OrchestratorState.RUNNING and time.time() < deadline:
        time.sleep(0.01)
    orchestrator.pause()
    assert orchestrator.state.state is OrchestratorState.PAUSED
    orchestrator.resume()
    assert orchestrator.state.state is OrchestratorState.RUNNING
    thread.join(timeout=30)
    assert not thread.is_alive()
    assert len(outcomes["results"]) == len(scenario.steps)


def test_stop(tmp_path, bus, db, all_capabilities, clock):
    orchestrator = _orchestrator(tmp_path, bus, db, all_capabilities, clock)
    orchestrator.create_session()
    orchestrator.prepare()
    orchestrator.stop()
    assert orchestrator.state.state is OrchestratorState.STOPPED


def test_recovery_reports_action_runner(tmp_path, bus, db, all_capabilities, clock):
    orchestrator = _orchestrator(tmp_path, bus, db, all_capabilities, clock)
    orchestrator.create_session()
    orchestrator.prepare()
    report = orchestrator.recover()
    assert report.success
    assert report.reverted_count >= 1
