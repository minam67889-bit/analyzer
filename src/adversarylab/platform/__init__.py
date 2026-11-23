"""Platform adapters (Windows host, Android device)."""

from __future__ import annotations

from .adb import AdbClient, AndroidTelemetry, FirewallArchitecture, FirewallState
from .base import (
    CaptureSource,
    FirewallTelemetryAdapter,
    InfrastructureBackend,
    InfrastructureStatus,
)
from .windows import (
    NpcapCaptureSource,
    TsharkAnalyzer,
    WfpController,
    WindowsCapabilityProbe,
    WinRtHotspotBackend,
)

__all__ = [
    "InfrastructureBackend",
    "InfrastructureStatus",
    "CaptureSource",
    "FirewallTelemetryAdapter",
    "AdbClient",
    "AndroidTelemetry",
    "FirewallArchitecture",
    "FirewallState",
    "WindowsCapabilityProbe",
    "WinRtHotspotBackend",
    "NpcapCaptureSource",
    "TsharkAnalyzer",
    "WfpController",
]
