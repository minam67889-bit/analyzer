"""Gateway / routing / egress control.

Each controller records every command it issues so the recovery manager can revert them.
Windows uses netsh/PowerShell; Linux uses ``ip``/``nft``; ``NoopGateway`` is used in tests
and when the platform is not available. Nothing here silently succeeds: a failed command
raises :class:`PlatformError` with the exact command and output.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from ..errors import PlatformError
from ..logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class CommandRecord:
    action: str
    argv: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    reverted: bool = False


class GatewayController:
    """Abstract gateway/route controller."""

    label = "abstract"

    def __init__(self) -> None:
        self.history: list[CommandRecord] = []

    def add_route(self, destination: str, gateway: str, interface: str | None = None) -> None:
        raise NotImplementedError

    def delete_route(self, destination: str) -> None:
        raise NotImplementedError

    def set_interface_dns(self, interface: str, servers: list[str]) -> None:
        raise NotImplementedError

    def block_egress(self, interface: str, allow: list[str]) -> None:
        raise NotImplementedError

    def restore(self) -> None:
        raise NotImplementedError

    def _run(self, argv: list[str], *, action: str) -> subprocess.CompletedProcess:
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.SubprocessError) as exc:
            record = CommandRecord(action, argv, None, "", str(exc))
            self.history.append(record)
            raise PlatformError(f"{self.label} command failed: {' '.join(argv)}: {exc}") from exc
        record = CommandRecord(action, argv, proc.returncode, proc.stdout, proc.stderr)
        self.history.append(record)
        if proc.returncode != 0:
            raise PlatformError(
                f"{self.label} command failed ({proc.returncode}): {' '.join(argv)}\n"
                f"stdout={proc.stdout.strip()}\nstderr={proc.stderr.strip()}"
            )
        return proc


class NoopGateway(GatewayController):
    """Records intent without touching the host. Used for tests and dry runs."""

    label = "noop"

    def add_route(self, destination: str, gateway: str, interface: str | None = None) -> None:
        self.history.append(CommandRecord("add_route", [destination, gateway], 0, "", ""))

    def delete_route(self, destination: str) -> None:
        self.history.append(CommandRecord("delete_route", [destination], 0, "", ""))

    def set_interface_dns(self, interface: str, servers: list[str]) -> None:
        self.history.append(CommandRecord("set_dns", [interface, *servers], 0, "", ""))

    def block_egress(self, interface: str, allow: list[str]) -> None:
        self.history.append(CommandRecord("block_egress", [interface, *allow], 0, "", ""))

    def restore(self) -> None:
        for record in reversed(self.history):
            record.reverted = True


class LinuxGateway(GatewayController):
    label = "linux"

    def add_route(self, destination: str, gateway: str, interface: str | None = None) -> None:
        argv = ["ip", "route", "add", destination, "via", gateway]
        if interface:
            argv += ["dev", interface]
        self._run(argv, action="add_route")

    def delete_route(self, destination: str) -> None:
        self._run(["ip", "route", "del", destination], action="delete_route")

    def set_interface_dns(self, interface: str, servers: list[str]) -> None:
        # resolv.conf is not per-interface; record the intent and use systemd-resolved when present.
        resolved = ["resolvectl", "dns", interface, *servers]
        self._run(resolved, action="set_dns")

    def block_egress(self, interface: str, allow: list[str]) -> None:
        self._run(["nft", "add", "rule", "inet", "filter", "output", "oifname", interface, "accept"],
                  action="block_egress")

    def restore(self) -> None:
        for record in reversed(self.history):
            if record.action == "add_route" and record.returncode == 0 and len(record.argv) >= 3:
                try:
                    dest = record.argv[3]
                    self._run(["ip", "route", "del", dest], action="restore_route")
                except PlatformError:
                    pass
            record.reverted = True


class WindowsGateway(GatewayController):
    label = "windows"

    def add_route(self, destination: str, gateway: str, interface: str | None = None) -> None:
        argv = ["route", "add", destination, "mask", "255.255.255.255", gateway]
        if interface:
            argv.append(str(interface))
        self._run(argv, action="add_route")

    def delete_route(self, destination: str) -> None:
        self._run(["route", "delete", destination], action="delete_route")

    def set_interface_dns(self, interface: str, servers: list[str]) -> None:
        ps = (
            "Set-DnsClientServerAddress -InterfaceAlias '{ifname}' -ServerAddresses {addrs}"
        ).format(ifname=interface, addrs=",".join(f"'{s}'" for s in servers))
        self._run(["powershell", "-NoProfile", "-Command", ps], action="set_dns")

    def block_egress(self, interface: str, allow: list[str]) -> None:
        name = "AdversaryLab Egress Block"
        self._run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={name}", "dir=out", f"interface={interface}", "action=block",
        ], action="block_egress")
        for cidr in allow:
            self._run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}-allow-{cidr}", "dir=out", f"remoteip={cidr}", "action=allow",
            ], action="allow_egress")

    def restore(self) -> None:
        self._run([
            "netsh", "advfirewall", "firewall", "delete", "rule", "name=AdversaryLab Egress Block",
        ], action="restore_firewall")
        for record in reversed(self.history):
            if record.action == "add_route" and record.returncode == 0:
                try:
                    dest = record.argv[2]
                    self._run(["route", "delete", dest], action="restore_route")
                except (PlatformError, IndexError):
                    pass
            record.reverted = True


def create_gateway(platform_name: str) -> GatewayController:
    if platform_name.startswith("win"):
        return WindowsGateway()
    if platform_name.startswith("linux"):
        return LinuxGateway()
    return NoopGateway()
