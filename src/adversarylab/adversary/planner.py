"""Assessment planner: automatic test selection and coverage accounting."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from ..core.capability import CapabilitySet
from ..tests.registry import CoverageRow, TestRegistry
from ..tests.spec import TestCategory, TestSpec


@dataclass
class AssessmentPlan:
    session_id: str
    selected: list[str] = field(default_factory=list)
    coverage: list[CoverageRow] = field(default_factory=list)

    @property
    def unsupported(self) -> list[CoverageRow]:
        return [r for r in self.coverage if r.status == "UNSUPPORTED"]

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "selected": list(self.selected),
            "unsupported": [r.to_dict() for r in self.unsupported],
            "skipped": [r.to_dict() for r in self.coverage if r.status == "SKIPPED"],
            "coverage": [r.to_dict() for r in self.coverage],
        }


class AssessmentPlanner:
    def __init__(
        self,
        registry: TestRegistry,
        capabilities: CapabilitySet,
        *,
        include_categories: Iterable[str] | None = None,
        exclude_test_ids: Iterable[str] | None = None,
        auto_select: bool = True,
    ) -> None:
        self.registry = registry
        self.capabilities = capabilities
        self.include_categories = set(include_categories) if include_categories else None
        self.exclude_test_ids = set(exclude_test_ids or [])
        self.auto_select = auto_select

    def plan(self, session_id: str) -> AssessmentPlan:
        plan = AssessmentPlan(session_id=session_id)
        for spec in self.registry.specs():
            row = self._evaluate_spec(spec)
            plan.coverage.append(row)
            if row.status == "SELECTED":
                plan.selected.append(spec.id)
        return plan

    def _evaluate_spec(self, spec: TestSpec) -> CoverageRow:
        if spec.id in self.exclude_test_ids:
            return CoverageRow(spec.id, spec.name, spec.category.value, "SKIPPED",
                               "excluded by configuration", spec.execution_mode.value)
        # The infrastructure baseline is a safety invariant: an assessment must
        # never run without the control that proves the lab path works. Category
        # filters scope optional techniques, not the baseline.
        baseline = spec.category is TestCategory.INFRA or spec.id == "LAB-BASELINE"
        if (self.include_categories and spec.category.value not in self.include_categories
                and not baseline):
            return CoverageRow(spec.id, spec.name, spec.category.value, "SKIPPED",
                               "category not selected", spec.execution_mode.value)
        missing = self.capabilities.missing(spec.required_capabilities)
        if missing:
            reason = "; ".join(f"{c.value}: {self.capabilities.reason(c)}" for c in missing)
            return CoverageRow(spec.id, spec.name, spec.category.value, "UNSUPPORTED",
                               reason, spec.execution_mode.value)
        return CoverageRow(spec.id, spec.name, spec.category.value, "SELECTED",
                           "all required capabilities available", spec.execution_mode.value)
