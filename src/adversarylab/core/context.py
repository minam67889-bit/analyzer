"""Ambient session/test context for correlation.

The capture pipeline tags events with the currently executing test id when the event does
not already carry one. A ``contextvars.ContextVar`` is used so background threads each
keep their own value.
"""

from __future__ import annotations

from contextvars import ContextVar

_current_test_id: ContextVar[str | None] = ContextVar("current_test_id", default=None)
_current_scenario_id: ContextVar[str | None] = ContextVar("current_scenario_id", default=None)


def set_current_test(test_id: str | None, scenario_id: str | None = None) -> None:
    _current_test_id.set(test_id)
    _current_scenario_id.set(scenario_id)


def get_current_test() -> str | None:
    return _current_test_id.get()


def get_current_scenario() -> str | None:
    return _current_scenario_id.get()


class test_context:
    """Context manager that sets and restores the current test id."""

    def __init__(self, test_id: str | None, scenario_id: str | None = None) -> None:
        self.test_id = test_id
        self.scenario_id = scenario_id
        self._token = None
        self._token_scenario = None

    def __enter__(self):
        self._token = _current_test_id.set(self.test_id)
        self._token_scenario = _current_scenario_id.set(self.scenario_id)
        return self

    def __exit__(self, *exc: object) -> None:
        if self._token is not None:
            _current_test_id.reset(self._token)
        if self._token_scenario is not None:
            _current_scenario_id.reset(self._token_scenario)
