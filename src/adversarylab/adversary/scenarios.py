"""Scenario definitions and sequential scenario runner."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..core.cancellation import CancellationToken
from ..core.results import TestResult
from ..logging_config import get_logger
from ..tests.module import TestContext, TestRunner

logger = get_logger(__name__)


@dataclass
class ScenarioStep:
    test_id: str
    description: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    continue_on_failure: bool = True


@dataclass
class Scenario:
    id: str
    name: str
    description: str
    profile_id: str
    steps: list[ScenarioStep] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "profile_id": self.profile_id,
            "steps": [
                {"test_id": s.test_id, "description": s.description, "params": dict(s.params)}
                for s in self.steps
            ],
        }


ContextFactory = Callable[[str, str | None], TestContext]


class ScenarioRunner:
    def __init__(
        self,
        *,
        registry: Any,
        context_factory: Callable[[str, str | None], TestContext],
        cancel_token: CancellationToken | None = None,
        observation_window: float = 6.0,
    ) -> None:
        self.registry = registry
        self.context_factory = context_factory
        self.cancel_token = cancel_token or CancellationToken()
        self.runner = TestRunner(observation_window=observation_window)

    def run(self, scenario: Scenario) -> list[TestResult]:
        results: list[TestResult] = []
        for index, step in enumerate(scenario.steps, start=1):
            self.cancel_token.raise_if_cancelled()
            logger.info("scenario step %d/%d: %s", index, len(scenario.steps), step.test_id,
                        extra={"lab_scenario": scenario.id, "lab_test": step.test_id})
            ctx = self.context_factory(step.test_id, scenario.id)
            module = self.registry.instantiate(step.test_id, ctx)
            result = self.runner.run(module)
            results.append(result)
            if result.verdict.value == "FAIL" and not step.continue_on_failure:
                break
        return results


_BUILTIN_SCENARIOS = [
    Scenario(
        id="passive-baseline",
        name="Passive baseline",
        description="Inventory destinations and confirm lab reachability.",
        profile_id="passive-observer",
        steps=[
            ScenarioStep("LAB-BASELINE", "Confirm lab reachability."),
            ScenarioStep("DISC-DNS-PASSIVE", "Build the destination inventory."),
        ],
    ),
    Scenario(
        id="dns-manipulation",
        name="DNS manipulation workflow",
        description="Spoof, rebind and leak-test DNS resolution.",
        profile_id="dns-manipulator",
        steps=[
            ScenarioStep("DNS-SPOOF-A", "Spoof an A record.", {"qname": "spoof.lab.test"}),
            ScenarioStep("DNS-REBIND-PRIVATE", "Rebind to a private address.",
                      {"qname": "rebind.lab.test"}),
            ScenarioStep("DNS-REBIND-CNAME", "Rebind via CNAME.",
                      {"qname": "cname.lab.test"}),
            ScenarioStep("DNS-LEAK-UNDERLYING", "Check for resolver leakage."),
        ],
    ),
    Scenario(
        id="rogue-infrastructure",
        name="Rogue infrastructure workflow",
        description="DHCP and gateway manipulation with recovery.",
        profile_id="rogue-infra",
        steps=[
            ScenarioStep("DHCP-ROGUE-GATEWAY", "Inject rogue DHCP options."),
            ScenarioStep("GW-IMPERSONATION", "Impersonate the gateway."),
            ScenarioStep("ARP-SPOOF-GATEWAY", "Poison ARP for the gateway."),
        ],
    ),
    Scenario(
        id="tls-validation",
        name="TLS validation workflow",
        description="Certificate and protocol validation scenarios.",
        profile_id="tls-adversary",
        steps=[
            ScenarioStep("TLS-WRONG-CERT", "Untrusted certificate."),
            ScenarioStep("TLS-WRONG-HOSTNAME", "Wrong hostname."),
            ScenarioStep("TLS-DOWNGRADE", "Legacy protocol."),
            ScenarioStep("TLS-PINNING", "Pinning behavior."),
        ],
    ),
    Scenario(
        id="multi-stage-aitm",
        name="Multi-stage adversary-in-the-middle",
        description="DNS then gateway manipulation, correlated.",
        profile_id="multi-stage",
        steps=[
            ScenarioStep("MULTI-STAGE-AITM", "Run the correlated chain.",
                      {"qname": "chain.lab.test"}),
        ],
    ),
]


class ScenarioLibrary:
    def __init__(self) -> None:
        self._scenarios: dict[str, Scenario] = {s.id: s for s in _BUILTIN_SCENARIOS}

    def register(self, scenario: Scenario) -> None:
        self._scenarios[scenario.id] = scenario

    def get(self, scenario_id: str) -> Scenario | None:
        return self._scenarios.get(scenario_id)

    def all(self) -> list[Scenario]:
        return sorted(self._scenarios.values(), key=lambda s: s.id)

    def to_dict(self) -> list[dict]:
        return [s.to_dict() for s in self.all()]
