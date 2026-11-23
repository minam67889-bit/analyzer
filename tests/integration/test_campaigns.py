from __future__ import annotations

from adversarylab.adversary.actions import FakeActionRunner
from adversarylab.adversary.campaigns import (
    CampaignLibrary,
    CampaignRunner,
    DynamicCampaignBuilder,
)
from adversarylab.adversary.orchestrator import Orchestrator, OrchestratorState
from adversarylab.config.schema import default_config
from adversarylab.tests.catalog import build_default_registry


def _orchestrator(tmp_path, bus, db, capabilities, clock) -> Orchestrator:
    config = default_config()
    config.tests.observation_window_seconds = 0.05
    return Orchestrator(
        config=config, registry=build_default_registry(), capabilities=capabilities,
        bus=bus, db=db, evidence_root=tmp_path / "evidence",
        action_runner=FakeActionRunner(), clock=clock,
    )


def test_predefined_campaigns_reference_known_tests():
    library = CampaignLibrary()
    assert len(library.all()) >= 5
    known = {spec.id for spec in build_default_registry().specs()}
    for campaign in library.all():
        assert campaign.stages, f"{campaign.id} has no stages"
        for stage in campaign.stages:
            assert stage.test_id in known, f"{campaign.id}:{stage.name} unknown {stage.test_id}"


def test_campaign_runner_preserves_state_and_reports_skip(tmp_path, bus, db, all_capabilities, clock):
    orchestrator = _orchestrator(tmp_path, bus, db, all_capabilities, clock)
    orchestrator.create_session()
    orchestrator.prepare()
    campaign = CampaignLibrary().get("cookie-exposure-plaintext")
    run = CampaignRunner(orchestrator).run(campaign)
    assert run.status == "completed"
    assert run.stages
    assert run.explanation
    # No device traffic exists in this fixture, so the first stage executes and later
    # stages that require an established exposure path are skipped with an explanation.
    assert run.stages[0].feasible is True
    skipped = [s for s in run.stages if not s.feasible]
    assert all("unmet prerequisite conditions" in s.note for s in skipped)
    assert run.objective_reached is False


def test_campaign_skips_stage_when_prerequisite_missing(tmp_path, bus, db, all_capabilities, clock):
    from adversarylab.adversary.campaigns import CampaignDefinition, CampaignStage

    orchestrator = _orchestrator(tmp_path, bus, db, all_capabilities, clock)
    orchestrator.create_session()
    orchestrator.prepare()
    campaign = CampaignDefinition(
        id="test-campaign", name="Test", description="Test", profile_id="observer",
        objective="exercise the skip path",
        stages=[
            CampaignStage(name="needs something impossible", description="x",
                           test_id="LAB-BASELINE", requires=["impossible_condition"]),
        ],
    )
    run = CampaignRunner(orchestrator).run(campaign)
    assert run.stages[0].feasible is False
    assert "impossible_condition" in run.stages[0].note
    assert run.objective_reached is False


def test_orchestrator_run_campaign_returns_to_ready(tmp_path, bus, db, all_capabilities, clock):
    orchestrator = _orchestrator(tmp_path, bus, db, all_capabilities, clock)
    orchestrator.create_session()
    orchestrator.prepare()
    campaign = CampaignLibrary().get("ipv6-bypass-chain")
    run = orchestrator.run_campaign(campaign)
    assert run.status == "completed"
    assert orchestrator.state.state is OrchestratorState.READY


def test_dynamic_builder_refuses_when_lab_unreachable():
    builder = DynamicCampaignBuilder(build_default_registry())
    campaign = builder.build(discovered_domains=[], lab_reachable=False,
                             plaintext_http_observed=False, tls_observed=False)
    assert campaign.stages == []
    assert "No campaign can proceed" in campaign.description or not campaign.stages


def test_dynamic_builder_builds_plaintext_chain():
    builder = DynamicCampaignBuilder(build_default_registry())
    campaign = builder.build(discovered_domains=["cookies.lab.test"], lab_reachable=True,
                             plaintext_http_observed=True, tls_observed=False)
    ids = [s.test_id for s in campaign.stages]
    assert "COOKIE-PLAINTEXT-EXPOSURE" in ids
    assert any(s.is_objective for s in campaign.stages)


def test_dynamic_builder_builds_tls_objective():
    builder = DynamicCampaignBuilder(build_default_registry())
    campaign = builder.build(discovered_domains=["secure.lab.test"], lab_reachable=True,
                             plaintext_http_observed=False, tls_observed=True)
    assert campaign.stages[-1].is_objective
    assert campaign.stages[-1].test_id == "COOKIE-HTTPS-ENCRYPTED"
