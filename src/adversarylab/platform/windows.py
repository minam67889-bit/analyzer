"""Windows platform adapters.

All Windows-only imports are lazy, so this module imports safely on Linux (used by the
test-suite with an injected command runner). Live behaviour requires Windows + Npcap +
administrator privileges.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..core.capability import Capability, CapabilityReport, CapabilitySet
from ..errors import PlatformError
from ..logging_config import get_logger
from .base import BackendState, InfrastructureStatus

logger = get_logger(__name__)

Runner = Callable[[list[str]], subprocess.CompletedProcess]


def _local_runner(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=60)


# ----------------------------------------------------------------------
# netsh parsing (pure functions, unit-tested)
# ----------------------------------------------------------------------
def parse_wlan_drivers(text: str) -> dict[str, Any]:
    """Parse ``netsh wlan show drivers`` output."""
    result: dict[str, Any] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        result[key] = value
    return {
        "hosted_network_supported": _parse_yes_no(result.get("Hosted network supported")),
        "soft_ap_supported": _parse_yes_no(result.get("Soft AP")),
        "monitor_mode_supported": _parse_yes_no(result.get("Network monitor mode")),
        "protected_management_frames": _parse_yes_no(result.get("Protected Management Frames")),
        "mac_randomization": _parse_yes_no(result.get("MAC Randomization")),
        "driver": result.get("Driver"),
        "driver_version": result.get("Driver version"),
        "raw": result,
    }


def parse_wireless_capabilities(text: str) -> dict[str, Any]:
    """Parse ``netsh wlan show wirelesscapabilities`` output."""
    result: dict[str, Any] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        result[key.strip()] = value.strip()
    return {
        "station": _parse_yes_no(result.get("Station")),
        "soft_ap": _parse_yes_no(result.get("Soft AP")),
        "monitor_mode": _parse_yes_no(result.get("Network monitor mode")),
        "pmf": _parse_yes_no(result.get("Protected Management Frames")),
        "mac_randomization": _parse_yes_no(result.get("MAC Randomization")),
        "raw": result,
    }


def parse_interface_list(text: str) -> list[dict[str, Any]]:
    """Parse ``netsh wlan show interfaces`` output into per-interface dicts."""
    interfaces: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for line in text.splitlines():
        if ":" not in line:
            if current:
                interfaces.append(current)
                current = {}
            continue
        key, value = line.split(":", 1)
        current[key.strip()] = value.strip()
    if current:
        interfaces.append(current)
    return interfaces


def _parse_yes_no(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"yes", "supported", "true", "enabled"}:
        return True
    if normalized in {"no", "not supported", "false", "disabled"}:
        return False
    return None


# ----------------------------------------------------------------------
# Capability probe
# ----------------------------------------------------------------------
class WindowsCapabilityProbe:
    def __init__(self, runner: Runner | None = None) -> None:
        self.runner = runner or _local_runner

    def _run(self, argv: list[str]) -> subprocess.CompletedProcess:
        return self.runner(argv)

    def run(self) -> CapabilitySet:
        capabilities = CapabilitySet()
        on_windows = sys.platform == "win32"
        if not on_windows:
            for cap in Capability:
                capabilities.add(CapabilityReport(
                    capability=cap, available=False,
                    reason="host is not Windows; live probe unavailable",
                ))
            return capabilities

        admin = self._is_admin()
        if not admin:
            for cap in Capability:
                capabilities.add(CapabilityReport(
                    capability=cap, available=False,
                    reason="administrator privileges required for live probe",
                ))
            return capabilities

        # Wireless adapter capabilities
        drivers: dict[str, Any] = {}
        caps: dict[str, Any] = {}
        try:
            proc = self._run(["netsh", "wlan", "show", "drivers"])
            drivers = parse_wlan_drivers(proc.stdout or "")
        except Exception as exc:
            logger.warning("netsh wlan show drivers failed: %s", exc)
        try:
            proc = self._run(["netsh", "wlan", "show", "wirelesscapabilities"])
            caps = parse_wireless_capabilities(proc.stdout or "")
        except Exception as exc:
            logger.warning("netsh wlan show wirelesscapabilities failed: %s", exc)

        hosted = drivers.get("hosted_network_supported") or caps.get("soft_ap")
        monitor = drivers.get("monitor_mode_supported") or caps.get("monitor_mode")
        pmf = drivers.get("protected_management_frames") or caps.get("pmf")

        capabilities.add(CapabilityReport(
            Capability.WIFI_HOTSPOT, True,
            reason="WinRT NetworkOperatorTetheringManager available", backend="winrt_hotspot",
        ))
        capabilities.add(CapabilityReport(
            Capability.WIFI_HOSTED_NETWORK, bool(hosted),
            reason="driver reports Soft AP/hosted network support" if hosted
            else "driver does not report Soft AP/hosted network support",
            backend="hosted_network", raw=drivers,
        ))
        capabilities.add(CapabilityReport(
            Capability.WIFI_MONITOR_MODE, bool(monitor),
            reason="adapter reports monitor mode" if monitor
            else "adapter does not report monitor mode",
            raw=drivers,
        ))
        capabilities.add(CapabilityReport(
            Capability.WIFI_INJECTION, bool(monitor),
            reason="injection requires a monitor-mode capable adapter" if monitor
            else "no monitor-mode adapter reported",
        ))
        capabilities.add(CapabilityReport(
            Capability.WIFI_PMF, bool(pmf),
            reason="adapter/driver reports Protected Management Frame support" if pmf
            else "adapter/driver does not report Protected Management Frame support",
            raw=drivers,
        ))
        capabilities.add(CapabilityReport(
            Capability.PACKET_CAPTURE, self._has_npcap()[0],
            reason=self._has_npcap()[1],
        ))
        capabilities.add(CapabilityReport(
            Capability.RAW_80211, bool(monitor) and self._has_npcap()[0],
            reason="raw 802.11 requires Npcap raw-802.11 option + monitor mode",
        ))
        capabilities.add(CapabilityReport(
            Capability.WFP_USER_MODE, True, reason="netsh/PowerShell WFP inspection available",
        ))
        capabilities.add(CapabilityReport(
            Capability.WFP_CALLOUT, False,
            reason="kernel callout driver requires WDK + signing; not implemented in v1",
        ))
        capabilities.add(CapabilityReport(
            Capability.ADB, self._has_command("adb")[0], reason=self._has_command("adb")[1],
        ))
        capabilities.add(CapabilityReport(
            Capability.ANDROID_ROOT, False,
            reason="root state is a device property, determined during device validation",
        ))
        capabilities.add(CapabilityReport(
            Capability.IPV4, True, reason="IPv4 stack present",
        ))
        capabilities.add(CapabilityReport(
            Capability.IPV6, self._has_ipv6(), reason="IPv6 interface with a global/ULA address present",
        ))
        capabilities.add(CapabilityReport(
            Capability.EXTERNAL_AP, True, reason="external AP backend is operator-configured",
        ))
        capabilities.add(CapabilityReport(
            Capability.HOSTAPD, self._has_command("hostapd")[0], reason=self._has_command("hostapd")[1],
        ))
        capabilities.add(CapabilityReport(
            Capability.HYPER_V, self._has_hyperv(), reason="Hyper-V optional feature state",
        ))
        capabilities.add(CapabilityReport(
            Capability.TSHARK, self._has_command("tshark")[0], reason=self._has_command("tshark")[1],
        ))
        capabilities.add(CapabilityReport(
            Capability.NETSH, self._has_command("netsh")[0], reason=self._has_command("netsh")[1],
        ))
        capabilities.add(CapabilityReport(
            Capability.POWERSHELL, self._has_command("powershell")[0],
            reason=self._has_command("powershell")[1],
        ))
        capabilities.add(CapabilityReport(
            Capability.LAB_CA, self._has_lab_ca(), reason="cryptography dependency availability",
        ))
        capabilities.add(CapabilityReport(
            Capability.LOOPBACK_CAPTURE, self._has_npcap()[0], reason=self._has_npcap()[1],
        ))
        capabilities.add(CapabilityReport(
            Capability.TLS_INTERCEPTION, False,
            reason="TLS interception is restricted to lab-controlled endpoints with explicit test trust",
        ))
        return capabilities

    # ------------------------------------------------------------------
    def _is_admin(self) -> bool:
        if sys.platform != "win32":
            return False
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _has_npcap(self) -> tuple[bool, str]:
        try:
            proc = self._run(["sc", "query", "npcap"])
            if proc.returncode == 0 and "RUNNING" in (proc.stdout or ""):
                return True, "npcap service present and running"
            if proc.returncode == 0:
                return True, "npcap service present but not running"
        except Exception:
            pass
        try:
            import scapy  # noqa: F401

            return True, "scapy/Npcap capture stack importable"
        except Exception:
            return False, "Npcap not detected (sc query npcap / scapy import failed)"

    def _has_command(self, command: str) -> tuple[bool, str]:
        try:
            proc = self._run([command, "--version"])
            if proc.returncode in (0, 1) and (proc.stdout or proc.stderr):
                return True, f"{command} available"
        except Exception:
            pass
        try:
            proc = self._run(["where.exe", command])
            if proc.returncode == 0:
                return True, f"{command} available"
        except Exception:
            pass
        return False, f"{command} not found on PATH"

    def _has_ipv6(self) -> bool:
        try:
            proc = self._run(["netsh", "interface", "ipv6", "show", "addresses"])
            text = proc.stdout or ""
            return "fd" in text.lower() or "2001:" in text.lower() or "fe80::" in text.lower()
        except Exception:
            return False

    def _has_hyperv(self) -> bool:
        try:
            proc = self._run(["powershell", "-NoProfile", "-Command",
                              "(Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).State"])
            return "Enabled" in (proc.stdout or "")
        except Exception:
            return False

    def _has_lab_ca(self) -> bool:
        try:
            import cryptography  # noqa: F401

            return True
        except Exception:
            return False


# ----------------------------------------------------------------------
# WinRT hotspot backend
# ----------------------------------------------------------------------
_WINRT_BRIDGE = r"""
[Windows.System.UserProfile.LockScreen,Windows.System.UserProfile,ContentType=WindowsRuntime] | Out-Null
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
Function Await($WinRtTask, $ResultType) {
  $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
  $netTask = $asTask.Invoke($null, @($WinRtTask))
  $netTask.Wait(-1) | Out-Null
  $netTask.Result
}
Function AwaitAction($WinRtAction) {
  $asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and !$_.IsGenericMethod })[0]
  $netTask = $asTask.Invoke($null, @($WinRtAction))
  $netTask.Wait(-1) | Out-Null
}
$profile = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()
if ($null -eq $profile) { Write-Output '{"error":"no internet connection profile"}'; exit 2 }
$manager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($profile)
$action = '__ACTION__'
switch ($action) {
  'start' {
    $result = Await ($manager.StartTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])
    Write-Output ('{"state":' + [int]$manager.TetheringOperationalState + ',"status":' + [int]$result.Status + ',"clients":' + $manager.ClientCount + '}')
  }
  'stop' {
    $result = Await ($manager.StopTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])
    Write-Output ('{"state":' + [int]$manager.TetheringOperationalState + ',"status":' + [int]$result.Status + '}')
  }
  'status' {
    $cfg = $manager.GetCurrentAccessPointConfiguration()
    Write-Output ('{"state":' + [int]$manager.TetheringOperationalState + ',"clients":' + $manager.ClientCount + ',"ssid":"' + $cfg.Ssid + '","passphrase":"' + $cfg.Passphrase + '"}')
  }
}
"""


@dataclass
class WinRtHotspotConfig:
    ssid: str = "AdversaryLab"
    passphrase: str = ""
    band: str = "auto"


class WinRtHotspotBackend:
    name = "winrt_hotspot"

    def __init__(self, runner: Runner | None = None) -> None:
        self.runner = runner or _local_runner
        self.config = WinRtHotspotConfig()
        self._status = InfrastructureStatus(BackendState.STOPPED, self.name)

    def _invoke(self, action: str) -> dict[str, Any]:
        script = _WINRT_BRIDGE.replace("__ACTION__", action)
        proc = self.runner(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script])
        out = (proc.stdout or "").strip()
        try:
            payload = json.loads(out.splitlines()[-1]) if out else {}
        except json.JSONDecodeError as exc:
            raise PlatformError(f"hotspot bridge returned non-JSON output: {out!r}") from exc
        if payload.get("error"):
            raise PlatformError(f"hotspot bridge error: {payload['error']}")
        return payload

    def start(self, config: Any) -> InfrastructureStatus:
        if isinstance(config, WinRtHotspotConfig):
            self.config = config
        payload = self._invoke("start")
        self._status = InfrastructureStatus(
            state=_state_from_int(payload.get("state", 0)),
            backend=self.name,
            ssid=self.config.ssid,
            details=payload,
        )
        return self._status

    def stop(self) -> None:
        try:
            self._invoke("stop")
        finally:
            self._status = InfrastructureStatus(BackendState.STOPPED, self.name)

    def status(self) -> InfrastructureStatus:
        payload = self._invoke("status")
        self._status = InfrastructureStatus(
            state=_state_from_int(payload.get("state", 0)),
            backend=self.name,
            ssid=payload.get("ssid") or self.config.ssid,
            clients=[{}] * int(payload.get("clients", 0) or 0),
            details=payload,
        )
        return self._status

    def configure(self, **kwargs: Any) -> None:
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)


def _state_from_int(value: int) -> BackendState:
    # TetheringOperationalState: Unknown=0, Off=1, On=2, InTransition=3
    return {
        1: BackendState.STOPPED,
        2: BackendState.RUNNING,
        3: BackendState.STARTING,
    }.get(int(value), BackendState.DEGRADED)


# ----------------------------------------------------------------------
# Capture sources
# ----------------------------------------------------------------------
class NpcapCaptureSource:
    name = "npcap"

    def __init__(self, runner: Runner | None = None) -> None:
        self.runner = runner or _local_runner
        self._thread = None
        self._stop = None

    def list_interfaces(self) -> list[dict[str, Any]]:
        try:
            from scapy.interfaces import get_working_ifaces

            return [
                {"name": iface.name, "description": getattr(iface, "description", ""),
                 "index": getattr(iface, "index", None)}
                for iface in get_working_ifaces()
            ]
        except Exception as exc:
            raise PlatformError(f"cannot enumerate capture interfaces: {exc}") from exc

    def start(self, sink: Callable[[bytes], None], *, interface: str | None = None,
              bpf: str | None = None) -> None:
        try:
            from scapy.all import sniff
        except Exception as exc:
            raise PlatformError(f"scapy is required for live Npcap capture: {exc}") from exc
        import threading

        self._stop = threading.Event()

        def _run() -> None:
            try:
                sniff(
                    iface=interface, filter=bpf, store=False,
                    prn=lambda pkt: sink(bytes(pkt)),
                    stop_filter=lambda _pkt: self._stop.is_set() if self._stop else False,
                )
            except Exception as exc:  # pragma: no cover
                logger.error("capture failed: %s", exc)

        self._thread = threading.Thread(target=_run, daemon=True, name="npcap-capture")
        self._thread.start()

    def stop(self) -> None:
        if self._stop:
            self._stop.set()
        if self._thread:
            self._thread.join(timeout=3.0)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


class TsharkAnalyzer:
    name = "tshark"

    def __init__(self, tshark_path: str = "tshark", runner: Runner | None = None) -> None:
        self.tshark_path = tshark_path
        self.runner = runner or _local_runner

    def analyze_offline(self, path: str, *, fields: list[str] | None = None) -> list[dict]:
        argv = [self.tshark_path, "-r", path, "-T", "json"]
        if fields:
            for field in fields:
                argv += ["-e", field]
        proc = self.runner(argv)
        if proc.returncode != 0:
            raise PlatformError(f"tshark failed: {proc.stderr.strip()}")
        try:
            parsed = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise PlatformError(f"tshark returned invalid JSON: {exc}") from exc
        return parsed if isinstance(parsed, list) else []

    def extract_dns(self, path: str) -> list[dict]:
        rows = self.analyze_offline(path, fields=[
            "dns.qry.name", "dns.a", "dns.aaaa", "dns.response.flags", "ip.dst",
        ])
        return [r for r in rows if "dns.qry.name" in json.dumps(r)]


class WfpController:
    """User-mode WFP inspection/control.

    Kernel callout support is explicitly not implemented; ``callout_supported`` is always
    False so capability gating can report it honestly.
    """

    name = "wfp_user_mode"
    callout_supported = False

    def __init__(self, runner: Runner | None = None) -> None:
        self.runner = runner or _local_runner

    def inspect(self) -> dict[str, Any]:
        proc = self.runner(["netsh", "wfp", "show", "state"])
        return {"returncode": proc.returncode, "output": proc.stdout or "", "stderr": proc.stderr or ""}

    def filters(self) -> str:
        proc = self.runner(["netsh", "wfp", "show", "filters"])
        return proc.stdout or ""

    def add_firewall_rule(self, name: str, direction: str, action: str, *,
                          remote_ip: str | None = None, interface: str | None = None) -> None:
        argv = ["netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}", f"dir={direction}", f"action={action}"]
        if remote_ip:
            argv.append(f"remoteip={remote_ip}")
        if interface:
            argv.append(f"interface={interface}")
        proc = self.runner(argv)
        if proc.returncode != 0:
            raise PlatformError(f"failed to add firewall rule: {proc.stderr.strip()}")
