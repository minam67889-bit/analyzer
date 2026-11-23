from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adversarylab.adversary.actions import FakeActionRunner  # noqa: E402
from adversarylab.clock import FrozenClock  # noqa: E402
from adversarylab.config.schema import default_config  # noqa: E402
from adversarylab.core.bus import EventBus  # noqa: E402
from adversarylab.core.capability import Capability, CapabilityReport, CapabilitySet  # noqa: E402
from adversarylab.core.store import Database  # noqa: E402
from adversarylab.tests.catalog import build_default_registry  # noqa: E402


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock()


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


@pytest.fixture
def config():
    return default_config()


@pytest.fixture
def registry():
    return build_default_registry()


@pytest.fixture
def runner() -> FakeActionRunner:
    return FakeActionRunner()


@pytest.fixture
def db(tmp_path):
    return Database(tmp_path / "test.db")


@pytest.fixture
def all_capabilities() -> CapabilitySet:
    return CapabilitySet(
        CapabilityReport(cap, True, "test fixture") for cap in Capability
    )
