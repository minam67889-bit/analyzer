# 05 — Windows & Hardware Feasibility Assessment

## 1. Windows edition/build requirements

| Requirement | Minimum | Recommended | Reason |
|---|---|---|---|
| Windows | 10 22H2 / 11 22H2 | Windows 11 23H2+ x64 | WinRT tethering stability, WFP, Npcap 1.7x+ |
| CPU | x64 dual-core | quad-core | Packet processing + DNS/DHCP + UI |
| RAM | 8 GiB | 16 GiB | Capture buffers, SQLite, UI |
| Disk | 20 GiB free | 50 GiB | PCAP evidence per session |
| Privileges | Administrator for hotspot/firewall/capture | same | WFP, Npcap, adapter control |
| Virtualization | Optional (Hyper-V/VM) | Optional | Lab isolation VMs |

## 2. Wireless adapter capability matrix (must be probed)

The app probes, per adapter:

- `netsh wlan show drivers` → `Hosted network supported`, `Soft AP`, `monitor mode`,
  `Protected Management Frames`, `DOT11k`, `MAC Randomization`.
- `netsh wlan show wirelesscapabilities` (where available).
- Npcap raw 802.11 availability.
- Driver version and date.

Decision logic:

```
if hotspot_backend.available and second_adapter.monitor_mode:
    backend = EXTERNAL_OR_DUAL_RADIO
elif hotspot_backend.available:
    backend = WINRT_HOTSPOT
    rf_injection = UNSUPPORTED
elif hosted_network.available:
    backend = HOSTED_NETWORK
else:
    backend = EXTERNAL_AP_REQUIRED
```

## 3. Capability gating (no silent substitution)

Every capability has an `available` flag, an `unsupported_reason`, and a set of
`prerequisites`. Tests declaring that capability are marked `UNSUPPORTED` or
`NOT_APPLICABLE` when unavailable, with the reason surfaced in the report. The platform
never converts an unavailable capability into a simulated pass.

## 4. Subsystem feasibility

| Subsystem | Feasible | Limitation |
|---|---|---|
| Lab Wi-Fi creation | Conditional on adapter | Intel AX* often lack Soft AP/monitor |
| Traffic capture | Yes | Npcap install + adapter binding |
| DNS/DHCP manipulation | Yes | Needs on-path position or lab DHCP/DNS |
| ARP/gateway manipulation | Yes | Needs two interfaces or external AP |
| Deauth/evil twin | Conditional | Needs monitor+inject radio |
| WFP telemetry | Yes | User-mode API only in v1 |
| WFP kernel callout | No (v1) | WDK + driver signing |
| ADB device telemetry | Yes | USB debugging authorization |
| Direct firewall decision read | Conditional | Depends on target firewall |
| Full automation | Yes | UI + orchestrator + scheduler |

## 5. Recommended reference lab

1. Windows 11 host running Adversary Lab (administrator).
2. USB Wi-Fi adapter A supporting AP mode for the lab network (or WinRT hotspot if the
   built-in adapter supports it).
3. USB Wi-Fi adapter B supporting monitor mode + injection for RF attacks and capture.
4. Optional: OpenWrt AP for rogue-AP/evil-twin scenarios with full control.
5. Android test device with the target firewall installed, USB debugging authorized.
6. All services (DNS/DHCP/HTTP/TLS/WebSocket) hosted by the lab on RFC1918 space.
7. Egress from the lab denied by default; only explicitly mapped lab services allowed.

## 6. Development-environment caveat

This workspace is Linux; therefore the Windows probes are implemented and unit-tested with
fixtures but their live output is not part of this baseline. The first on-target run must
execute `adversarylab capability-probe` and attach the JSON to the validation record.
