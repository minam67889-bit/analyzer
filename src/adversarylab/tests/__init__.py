"""Plugin-based adversarial test framework."""

from __future__ import annotations

from .catalog import build_default_registry
from .module import TestContext, TestModule, TestRunner
from .registry import CoverageRow, TestRegistry
from .spec import TestCategory, TestSpec

__all__ = [
    "TestCategory",
    "TestSpec",
    "TestContext",
    "TestModule",
    "TestRunner",
    "TestRegistry",
    "CoverageRow",
    "build_default_registry",
]
