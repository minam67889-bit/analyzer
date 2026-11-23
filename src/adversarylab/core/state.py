"""Generic finite state machine with explicit transitions."""

from __future__ import annotations

from enum import Enum
from typing import Generic, TypeVar

from ..errors import OrchestratorError

S = TypeVar("S", bound=Enum)


class TransitionError(OrchestratorError):
    pass


class StateMachine(Generic[S]):
    def __init__(self, initial: S, transitions: dict[S, set[S]]) -> None:
        self._state = initial
        self._transitions = {k: set(v) for k, v in transitions.items()}
        self._on_enter: dict[S, list] = {}

    @property
    def state(self) -> S:
        return self._state

    def can_transition(self, to: S) -> bool:
        return to in self._transitions.get(self._state, set())

    def transition(self, to: S) -> None:
        if not self.can_transition(to):
            raise TransitionError(f"illegal transition {self._state} -> {to}")
        self._state = to
        for cb in self._on_enter.get(to, []):
            cb()

    def on_enter(self, state: S, callback) -> None:
        self._on_enter.setdefault(state, []).append(callback)
