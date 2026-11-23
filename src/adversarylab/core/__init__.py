"""Core primitives: events, verdicts, capabilities, plugins, cancellation, state."""

from __future__ import annotations

from .bus import EventBus, EventFilter
from .cancellation import CancellationToken
from .capability import Capability, CapabilityReport, CapabilitySet
from .events import EventCategory, EventSeverity, EventSource, NetworkEvent
from .results import (
    BlockCause,
    Confidence,
    ExecutionMode,
    Observation,
    TestResult,
    Verdict,
    VerdictEngine,
)
from .state import StateMachine, TransitionError

__all__ = [
    "EventBus",
    "EventFilter",
    "NetworkEvent",
    "EventCategory",
    "EventSeverity",
    "EventSource",
    "Capability",
    "CapabilityReport",
    "CapabilitySet",
    "CancellationToken",
    "Verdict",
    "Confidence",
    "BlockCause",
    "ExecutionMode",
    "Observation",
    "TestResult",
    "VerdictEngine",
    "StateMachine",
    "TransitionError",
]
