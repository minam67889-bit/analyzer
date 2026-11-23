"""Cooperative cancellation used by the orchestrator and background workers."""

from __future__ import annotations

import threading

from ..errors import OrchestratorError


class CancellationToken:
    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            raise OrchestratorError("operation cancelled")

    def wait(self, timeout: float | None = None) -> bool:
        """Block until cancelled or timeout. Returns True if cancelled."""
        return self._event.wait(timeout)

    def reset(self) -> None:
        self._event.clear()
