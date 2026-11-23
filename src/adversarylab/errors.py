"""Structured error taxonomy.

Every subsystem raises a subclass of :class:`LabError` so the UI, CLI and orchestrator can
present actionable messages instead of raw tracebacks.
"""

from __future__ import annotations


class LabError(Exception):
    """Base class for all Adversary Lab errors."""


class ConfigError(LabError):
    """Configuration is missing, malformed, or semantically invalid."""


class ValidationError(LabError):
    """A value failed validation (scope, address, scenario parameter)."""


class CapabilityError(LabError):
    """A required capability is unavailable on this host."""


class PlatformError(LabError):
    """A platform adapter failed (netsh, WinRT, Npcap, WFP, ADB)."""


class EvidenceError(LabError):
    """Evidence could not be written, hashed, or verified."""


class TestError(LabError):
    """A test module failed to load, validate, or execute."""

    # Not a pytest test class despite the Test* prefix.
    __test__ = False


class OrchestratorError(LabError):
    """The orchestrator entered an illegal state or failed to recover."""


class RecoveryError(LabError):
    """Recovery of the laboratory or network state failed."""


class SafetyError(LabError):
    """An operation would violate laboratory scope or isolation invariants."""
