# 04 — Technology Comparison & Selection

## 1. Laboratory infrastructure backends

| Backend | AP mode | Monitor/inject | IPv6 | Automation | Verdict |
|---|---|---|---|---|---|
| Windows Mobile Hotspot (WinRT) | Yes, if adapter supports | No (shared radio) | Yes | Full (WinRT/PowerShell) | **Primary** |
| Legacy hosted network (`netsh wlan`) | Rarely | No | Partial | netsh | Fallback/probe only |
| External managed AP (OpenWrt/enterprise) | Yes | Separate sensor radio | Yes | SSH/REST | **Recommended for wireless attacks** |
| Linux host + hostapd (VM/Hyper-V) | Yes | With second adapter | Yes | Full | Strong alternative backend |
| Hyper-V virtual switch | Virtual only | No raw 802.11 | Yes | Full | Not sufficient alone for RF attacks |

**Selection rule:** the app probes capabilities at startup and chooses the strongest
available backend; it never pretends a backend provides RF injection when it does not.

## 2. Capture / analysis

| Tool | Role | Machine-readable | Windows | Verdict |
|---|---|---|---|---|
| Npcap | Capture driver | via libpcap | Yes | Adopt |
| Scapy | Craft/inject/parse | Python | With Npcap | Adopt (optional import) |
| TShark | Field extraction | `-T json/fields` | Yes | Adopt as optional analyzer |
| Pure-Python PCAP/PCAPNG reader | Offline evidence | Yes | Cross-platform | Adopt (no Npcap needed for evidence) |
| Raw sockets | L2/L3 injection | Python | Windows limited | Scapy/Npcap instead |

## 3. Host network control

| Option | Per-app filtering | Kernel driver | Signing | Verdict |
|---|---|---|---|---|
| WFP user-mode (`Fwpm*`) | Yes | No | No | Adopt for telemetry/rules |
| WFP callout driver | Yes + DPI | Yes | Yes (WHQL/attestation) | Document as unsupported v1 |
| Windows Firewall COM/netsh | Yes | No | No | Adopt for egress controls |
| netsh route/adapter | Routing only | No | No | Adopt for route manipulation |

## 4. Android integration

| Method | Needs root | Needs USB | Granularity | Verdict |
|---|---|---|---|---|
| ADB (dumpsys, logcat, pm) | No | Yes | Device/VPN state, app list | Adopt |
| ADB shell ip route/rule | No (limited) | Yes | Routing view | Adopt |
| Root shell (iptables/nft, per-UID counters) | Yes | Optional | True firewall telemetry | Conditional adapter |
| Firewall app API/logs | Varies | No | Decisions | Conditional adapter |
| External capture | No | No | Ground truth | Adopt as primary corroboration |

## 5. Lab services

| Service | Implementation | Why |
|---|---|---|
| DNS | Built-in authoritative/recursive responder | Zero external deps; controllable TTL/spoof; logging |
| DHCP | Built-in DHCPOFFER/ACK responder | Deterministic leases and option injection |
| HTTP/WebSocket | Python `http.server` + custom WS | Lab endpoints, captive portal, Host/SNI routing |
| TLS | `ssl` + generated lab CA | Trust/validation tests with explicit test trust |
| Gateway/NAT | OS routing + firewall rules | Reproducible; rolled back on recovery |

## 6. UI technology

| Option | Verdict |
|---|---|
| PySide6 | Adopt — mature, signals/slots map cleanly to the event bus, cross-platform code |
| C# WPF/WinUI | Rejected for v1 — would fragment the core; may be revisited for a shell |
| Web UI (Electron/Tauri) | Rejected — adds a browser stack with no security-testing benefit |
| Tkinter | Rejected — insufficient for a professional multi-pane tool |

## 7. Language / packaging

Python 3.12+ is the target (3.11 supported for this workspace). Packaging via `pyproject.toml`
with optional extras (`windows`, `ui`, `dev`). Windows installer via `msix`/`nsis` documented
but not produced in this workspace. Reproducible builds via locked `requirements.lock`.
