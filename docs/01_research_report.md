# 01 — Independent Research & Feasibility Report

## 1. Method

The research phase used primary/authoritative sources only: Microsoft Learn (WFP, WinRT
tethering, Npcap/Wireshark), Android developer reference (VpnService, ConnectivityManager,
Private DNS), IETF RFCs, IEEE 802.11 amendments, MITRE ATT&CK, OWASP MASVS/MASTG, NIST
publications, and peer-reviewed/academic work. Every claim about an API capability in the
codebase is traceable to a source in `docs/12_bibliography.md`.

Environment inspected first (per directive §19):

| Item | Observed value |
|---|---|
| OS | Debian GNU/Linux 12 (bookworm), kernel 6.1.158 x86_64 |
| Python | 3.11.2 |
| CPU / RAM | 2 cores, 3.8 GiB |
| Disk | 21 GiB, ~20 GiB free |
| Windows | **Not present** (this is a Linux sandbox) |
| Wireless adapters | none visible |
| Npcap/WinPcap | not present |
| Wireshark/TShark, Nmap, ADB, PowerShell, .NET | not installed |
| GitHub auth | `gh` authenticated as `minam67889-bit` |

Consequence: Windows-specific subsystems are implemented against documented APIs and are
unit-tested with mocked boundaries, but cannot be *executed* in this workspace. This is
recorded as a hard limitation and a prerequisite for on-target validation.

## 2. Findings by technology area

### 2.1 Windows Filtering Platform (WFP)

WFP is the correct layer for host-side network telemetry and control. It exposes a
user-mode filtering engine (~10 layers) plus a kernel-mode engine (~50 layers), managed by
the Base Filtering Engine service (`bfe.dll`). It supports per-application filtering,
ALE layers, transport/network layers, MAC-layer filtering since Windows 8, and vSwitch
filtering since Windows 8. Custom logic beyond permit/block requires a kernel callout
driver (`Fwps*` APIs) — which requires the Windows Driver Kit, a signing strategy, and
elevation. **Decision:** use the user-mode `Fwpm*` management API and netsh for
capability/state inspection, and treat callout drivers as an explicitly unsupported
advanced extension with a documented reason, rather than pretending to implement kernel
filtering.

### 2.2 Windows Wi-Fi / hotspot

- Legacy **Wireless Hosted Network** (`netsh wlan ... hostednetwork`) depends on Virtual
  Wi-Fi/Soft AP support that most modern drivers (notably Intel) do not expose.
- Modern **Mobile Hotspot** uses Wi-Fi Direct / tethering architecture and is driven by
  `Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager`
  (`StartTetheringAsync`, `StopTetheringAsync`, `GetCurrentAccessPointConfiguration`,
  `TetheringOperationalState`). It is callable from PowerShell/WinRT and is the primary
  backend.
- Monitor mode and raw 802.11 injection are **not** generally available on the same adapter
  as hotspot operation; Npcap's "raw 802.11" option plus an adapter that supports monitor
  mode is required.

**Decision:** multi-backend infrastructure abstraction. Primary = WinRT tethering;
secondary = external managed AP / OpenWrt (documented integration); tertiary = hosted
network where the driver reports support. Capability detection is mandatory before any
claim.

### 2.3 Packet capture

Npcap is the maintained NDIS 6 Light-Weight Filter successor to WinPcap, API-compatible
with WinPcap/libpcap, and is what Wireshark uses on Windows. Raw 802.11 capture depends on
adapter/driver and on the Npcap install option. Scapy on Windows requires Npcap and uses
`monitor=True` for 802.11 sockets. **Decision:** Npcap is the capture backend; TShark is an
optional machine-readable analyzer; a pure-Python classic-PCAP/PCAPNG reader is included
for offline evidence so evidence tooling has no hard dependency on Npcap.

### 2.4 Android firewall architectures

| Architecture | Mechanism | Strengths | Weaknesses relevant to testing |
|---|---|---|---|
| VPNService | TUN interface, userspace network stack | No root; per-app allow/deny lists; route/DNS control | IPv6 leak if `addRoute` omits `::/0`; DNS leak during tunnel setup; Private DNS can override resolver; `protect()` needed to avoid loop; only one VPN at a time |
| Root / iptables-nft | Kernel netfilter, per-UID | True per-UID control; can see traffic VPN apps cannot | Requires root; custom ROM/kernel concerns |
| Private DNS (DoT) | System resolver on TCP 853 | System-wide encrypted DNS | Domain-only control; can conflict with VPN; not an IP firewall |
| Accessibility/other | Non-network | — | Not a real firewall; out of scope for network verdicts |

The platform therefore does **not** assume VPNService. It builds evaluation adapters for
VPNService, root/iptables telemetry, and ADB-visible firewall logs, and it uses external
packet capture as the independent evidence source when internal decisions are invisible.

### 2.5 DNS

Plaintext DNS (UDP/TCP 53) is fully observable in-lab. DoH (RFC 8484), DoT (RFC 7858) and
DoQ (RFC 9250) encrypt or encapsulate queries; the platform can observe destinations,
TLS metadata and timing but must not claim to see query names inside an encrypted
transport unless the client sends plaintext. Tests distinguish DNS manipulation from
DNS-level rejection and from firewall-level rejection.

### 2.6 TLS / HTTP

TLS 1.3 (RFC 8446) with encrypted SNI (ESNI/ECH) and QUIC (RFC 9000) / HTTP/3 (RFC 9114)
reduce plaintext metadata. The platform extracts what is legitimately observable (SNI in
clear, ALPN, certificate chain, JA3/JA4-style fingerprint, handshake failure codes) and
explicitly flags encrypted payloads as opaque. TLS interception experiments are only run
against lab-controlled servers with explicitly configured test trust, never against
third-party endpoints.

### 2.7 Wireless security

802.11 management frames (deauth/disassoc) were unauthenticated by design; 802.11w (PMF)
adds MIC protection and is mandatory in WPA3. Evil-twin/KARMA attacks exploit SSID trust,
not encryption. Testing must therefore include PMF state, downgrade (WPA3→WPA2),
rogue BSSID/SSID, captive-portal cloning, and forced-reconnect behavior.

## 3. Feasibility conclusions

| Capability | Feasible in-app? | Notes |
|---|---|---|
| Create/manage lab Wi-Fi | Yes, conditional | WinRT hotspot on capable hardware; else external AP |
| Capture lab traffic | Yes | Npcap on Windows; pure-Python pcap reader for evidence |
| DHCP/DNS/HTTP/TLS lab services | Yes | Implemented, testable cross-platform |
| DNS manipulation/spoofing | Yes | Lab DNS server + rogue responder |
| ARP poisoning / gateway impersonation | Yes | Requires two interfaces or external AP |
| Deauth / evil twin | Yes with caveats | Needs monitor mode + injection adapter; otherwise marked hardware-dependent |
| WFP kernel callouts | Not in v1 | WDK + signing; documented limitation |
| Direct read of firewall decision | Sometimes | Depends on firewall; external capture is the fallback |
| Full automation | Yes | Orchestrator with pause/resume/stop/emergency |

## 4. Risks

1. **Hardware variance** is the dominant risk: AP/monitor/injection support is adapter- and
   driver-specific. Mitigation: capability gating and a coverage matrix that downgrades
   unsupported rows instead of faking them.
2. **Single-VPN constraint on Android** means the test device can run only one VPN; the
   lab controller must not require a second VPN on the device.
3. **False certainty** from one observation source. Mitigation: multi-source correlation and
   explicit confidence.
4. **Clock skew** between Windows host and Android device. Mitigation: NTP/`adb shell date`
   reconciliation and skew recording.
5. **Scope creep / accidental external targeting.** Mitigation: ownership boundary
   enforcement, allowlist-based active testing, and emergency shutdown.
