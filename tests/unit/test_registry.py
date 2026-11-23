from __future__ import annotations

import pytest

from adversarylab.errors import TestError
from adversarylab.tests.catalog import build_default_registry
from adversarylab.tests.registry import TestRegistry


def test_builtin_catalog_discovered():
    registry = build_default_registry()
    assert len(registry) >= 20
    ids = {spec.id for spec in registry.specs()}
    assert {"LAB-BASELINE", "DNS-SPOOF-A", "TLS-WRONG-CERT", "MULTI-STAGE-AITM"} <= ids


def test_unknown_test_raises():
    with pytest.raises(TestError):
        build_default_registry().get("NOPE")


def test_register_abstract_base_rejected():
    class NoSpec:
        pass

    registry = TestRegistry()
    with pytest.raises(TestError):
        registry.register(NoSpec)  # type: ignore[arg-type]


def test_duplicate_id_overrides():
    registry = build_default_registry()
    module = registry.get("LAB-BASELINE")

    class Copy(module):  # type: ignore[misc, valid-type]
        pass

    registry.register(Copy)
    assert registry.get("LAB-BASELINE") is Copy
