"""ADB-backed Android telemetry.

The client is transport-injectable so tests can supply a fake runner. Every command is
recorded in ``self.command_log`` and can be exported as evidence. No device-side
modification happens unless an explicit method is called.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from ..clock import Clock, SystemClock
from ..errors import PlatformError
from ..logging_config import get_logger

logger = get_logger(__name__)

Runner = Callable[[list[str]], "subprocess.CompletedProcess"]


class FirewallArchitecture(str, Enum):
    UNKNOWN = "unknown"
    VPN_SERVICE = "vpnservice"
    ROOT = "root"
    PRIVATE_DNS = "private_dns"
    API = "api"


@dataclass
class FirewallState:
    architecture: FirewallArchitecture
    package: str | None
    always_on: bool
    lockdown: bool
    private_dns_mode: str
    private_dns_specifier: str | None
    vpn_interface: str | None
    vpn_routes: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


class AdbClient:
    def __init__(
        self,
        adb_path: str = "adb",
        *,
        runner: Runner | None = None,
        clock: Clock | None = None,
    ) -> None:
        self.adb_path = adb_path
        self.runner = runner or self._default_runner
        self.clock = clock or SystemClock()
        self.command_log: list[dict] = []

    @staticmethod
    def _default_runner(argv: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(argv, capture_output=True, text=True, timeout=30)

    def _run(self, argv: list[str], *, check: bool = False) -> subprocess.CompletedProcess:
        proc = self.runner(argv)
        self.command_log.append({
            "timestamp": self.clock.now().isoformat(),
            "argv": list(argv),
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        })
        if check and proc.returncode != 0:
            raise PlatformError(f"adb command failed: {' '.join(argv)}: {proc.stderr.strip()}")
        return proc

    def devices(self) -> list[dict]:
        proc = self._run([self.adb_path, "devices", "-l"])
        devices = []
        for line in proc.stdout.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            serial = parts[0]
            state = parts[1]
            props = {}
            for extra in parts[2:]:
                if ":" in extra:
                    key, value = extra.split(":", 1)
                    props[key] = value
            devices.append({"serial": serial, "state": state, **props})
        return devices

    def select_device(self, serial: str = "") -> str:
        if serial:
            return serial
        devices = [d for d in self.devices() if d.get("state") == "device"]
        if not devices:
            raise PlatformError("no authorized Android device is connected via ADB")
        if len(devices) > 1:
            raise PlatformError(
                "multiple devices connected; specify device.adb_serial: "
                + ", ".join(d["serial"] for d in devices)
            )
        return devices[0]["serial"]

    def _adb(self, serial: str, *args: str) -> list[str]:
        return [self.adb_path, "-s", serial, *args]

    def shell(self, serial: str, command: str, *, check: bool = False) -> str:
        proc = self._run(self._adb(serial, "shell", command), check=check)
        return proc.stdout

    def getprop(self, serial: str, name: str) -> str:
        return self.shell(serial, f"getprop {name}").strip()

    def dumpsys(self, serial: str, service: str) -> str:
        return self.shell(serial, f"dumpsys {service}")

    def pull(self, serial: str, remote: str, local: str) -> None:
        self._run(self._adb(serial, "pull", remote, local), check=True)

    def logcat(self, serial: str, lines: int = 200, *, filterspec: str | None = None) -> str:
        cmd = f"logcat -d -t {int(lines)}"
        if filterspec:
            cmd += f" {filterspec}"
        return self.shell(serial, cmd)

    def date_seconds(self, serial: str) -> float:
        out = self.shell(serial, "date +%s.%N").strip()
        try:
            return float(out.splitlines()[-1])
        except (ValueError, IndexError) as exc:
            raise PlatformError(f"could not parse device date: {out!r}") from exc


class AndroidTelemetry:
    def __init__(self, client: AdbClient, serial: str = "", *, clock: Clock | None = None) -> None:
        self.client = client
        self.serial = serial
        self.clock = clock or SystemClock()

    def _serial(self) -> str:
        return self.serial or self.client.select_device()

    def device_info(self) -> dict:
        serial = self._serial()
        keys = {
            "model": "ro.product.model",
            "manufacturer": "ro.product.manufacturer",
            "android_version": "ro.build.version.release",
            "sdk": "ro.build.version.sdk",
            "fingerprint": "ro.build.fingerprint",
            "security_patch": "ro.build.version.security_patch",
            "hardware": "ro.hardware",
        }
        info = {"serial": serial}
        for key, prop in keys.items():
            info[key] = self.client.getprop(serial, prop)
        return info

    def routes(self) -> list[str]:
        return [line for line in self.client.shell(self._serial(), "ip route show table all").splitlines() if line.strip()]

    def addresses(self) -> list[str]:
        return [line for line in self.client.shell(self._serial(), "ip -br addr").splitlines() if line.strip()]

    def vpn_state(self) -> dict:
        serial = self._serial()
        dumpsys = self.client.dumpsys(serial, "connectivity")
        vpn_iface = None
        routes: list[str] = []
        always_on = self.client.shell(serial, "settings get global always_on_vpn_app").strip()
        lockdown = self.client.shell(serial, "settings get global always_on_vpn_lockdown").strip()
        for line in dumpsys.splitlines():
            if "VPN" in line and "Interface" in line:
                match = re.search(r"Interface[=:]\s*(\S+)", line)
                if match:
                    vpn_iface = match.group(1)
        for line in self.routes():
            if vpn_iface and vpn_iface in line:
                routes.append(line.strip())
        return {
            "vpn_interface": vpn_iface,
            "vpn_routes": routes,
            "always_on_vpn_app": None if always_on in {"null", ""} else always_on,
            "always_on_vpn_lockdown": lockdown not in {"null", "0", ""},
        }

    def private_dns(self) -> dict:
        serial = self._serial()
        mode = self.client.shell(serial, "settings get global private_dns_mode").strip()
        specifier = self.client.shell(serial, "settings get global private_dns_specifier").strip()
        return {
            "mode": mode,
            "specifier": None if specifier in {"null", ""} else specifier,
        }

    def installed_packages(self) -> list[str]:
        out = self.client.shell(self._serial(), "pm list packages")
        return [line.split(":", 1)[1].strip() for line in out.splitlines() if ":" in line]

    def detect_firewall_architecture(self, package_hint: str = "") -> FirewallState:
        serial = self._serial()
        packages = self.installed_packages()
        vpn = self.vpn_state()
        private_dns = self.private_dns()
        appops = self.client.shell(serial, "appops get").lower()
        architecture = FirewallArchitecture.UNKNOWN
        package = package_hint or None
        evidence: list[str] = []
        if package and package not in packages:
            evidence.append(f"hint package {package} is not installed on the device")
        if vpn.get("vpn_interface") or vpn.get("always_on_vpn_app"):
            architecture = FirewallArchitecture.VPN_SERVICE
            package = package or vpn.get("always_on_vpn_app")
            evidence.append(f"vpn_interface={vpn.get('vpn_interface')}")
        if "activate_vpn" in appops or "android:activate_vpn" in appops:
            if architecture is FirewallArchitecture.UNKNOWN:
                architecture = FirewallArchitecture.VPN_SERVICE
            evidence.append("appops activate_vpn present")
        if self.client.shell(serial, "su -c id").strip().startswith("uid=0"):
            architecture = FirewallArchitecture.ROOT
            evidence.append("root shell available")
        if private_dns.get("mode") == "hostname":
            evidence.append(f"private_dns={private_dns.get('specifier')}")
            if architecture is FirewallArchitecture.UNKNOWN:
                architecture = FirewallArchitecture.PRIVATE_DNS
        return FirewallState(
            architecture=architecture,
            package=package,
            always_on=bool(vpn.get("always_on_vpn_app")),
            lockdown=bool(vpn.get("always_on_vpn_lockdown")),
            private_dns_mode=private_dns.get("mode", ""),
            private_dns_specifier=private_dns.get("specifier"),
            vpn_interface=vpn.get("vpn_interface"),
            vpn_routes=vpn.get("vpn_routes", []),
            evidence=evidence,
        )

    def read_logcat(self, lines: int = 300) -> list[str]:
        try:
            return self.client.logcat(self._serial(), lines=lines).splitlines()
        except Exception:
            return []
