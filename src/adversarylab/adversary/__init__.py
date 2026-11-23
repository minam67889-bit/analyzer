"""Adversary emulation engine: profiles, actions, scenarios, orchestrator."""

from __future__ import annotations

from .actions import (
    ActionResult,
    FakeActionRunner,
    LabActionRunner,
    ServiceBackedActionRunner,
    SinkHandle,
)
from .orchestrator import AssessmentResult, Orchestrator, OrchestratorState
from .profiles import AdversaryProfile, ProfileLibrary
from .recovery import RecoveryManager
from .scenarios import Scenario, ScenarioRunner, ScenarioStep

__all__ = [
    "ActionResult",
    "LabActionRunner",
    "ServiceBackedActionRunner",
    "FakeActionRunner",
    "SinkHandle",
    "AdversaryProfile",
    "ProfileLibrary",
    "Scenario",
    "ScenarioStep",
    "ScenarioRunner",
    "Orchestrator",
    "OrchestratorState",
    "AssessmentResult",
    "RecoveryManager",
]
