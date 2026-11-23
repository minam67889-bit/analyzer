"""Abstract platform interfaces."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol


class BackendState(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    DEGRADED = "degraded"
    FAILED = "failed"


@dataclass
class InfrastructureStatus:
    state: BackendState
    backend: str
    ssid: str | None = None
    bssid: str | None = None
    channel: int | None = None
    clients: list[dict] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    message: str = ""


class InfrastructureBackend(Protocol):
    name: str

    def start(self, config: Any) -> InfrastructureStatus: ...
    def stop(self) -> None: ...
    def status(self) -> InfrastructureStatus: ...
    def configure(self, **kwargs: Any) -> None: ...


class CaptureSource(Protocol):
    name: str

    def list_interfaces(self) -> list[dict[str, Any]]: ...
    def start(self, sink: Callable[[bytes], None], *, interface: str | None = None,
              bpf: str | None = None) -> None: ...
    def stop(self) -> None: ...
    @property
    def running(self) -> bool: ...


class FirewallTelemetryAdapter(Protocol):
    name: str

    def device_info(self) -> dict[str, Any]: ...
    def vpn_state(self) -> dict[str, Any]: ...
    def rules_snapshot(self) -> dict[str, Any]: ...
    def logs(self, *, lines: int = 200) -> list[str]: ...
