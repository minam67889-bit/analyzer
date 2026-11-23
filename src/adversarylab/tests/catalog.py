"""Default test catalog discovery."""

from __future__ import annotations

from .registry import TestRegistry

BUILTIN_PACKAGE = "adversarylab.tests.builtin"


def build_default_registry() -> TestRegistry:
    registry = TestRegistry()
    try:
        registry.discover_package(BUILTIN_PACKAGE)
    except Exception:
        # Discovery is best-effort; a broken optional plugin must not prevent startup.
        pass
    return registry
