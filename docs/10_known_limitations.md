# 10 — Known Limitations (exact reasons and alternatives)

| # | Limitation | Exact technical reason | Strongest available alternative |
|---|---|---|---|
| 1 | No live Windows execution in this workspace | Sandbox is Linux; no Windows kernel/WFP/Npcap/hotspot | Implement against documented APIs + on-target validation; mocks for CI |
| 2 | WFP kernel callout driver not implemented | Requires WDK, kernel-mode code, driver signing/attestation, and elevated test hardware | User-mode `Fwpm*` + Windows Firewall + netsh; document callout as extension |
| 3 | Deauth/evil-twin not verifiable here | Requires monitor mode + raw 802.11 injection radio and Npcap raw-802.11 option | Hardware-gated implementation via Scapy; external OpenWrt sensor |
| 4 | Direct firewall decision read unavailable for many products | Firewall internals are proprietary; no standard Android API exposes per-connection decisions | External capture as ground truth + optional log/API adapter |
| 5 | Encrypted DNS payload not observable | DoH/DoT/DoQ encrypt queries; observing names would require MITM or client cooperation | Observe destination/TLS/timing; test resolver selection and leak paths |
| 6 | TLS application payload not decrypted | TLS 1.3 + ECH; third-party MITM is out of scope and often illegal | Lab-controlled endpoints with explicit test trust; handshake/SNI/ALPN/cert metadata |
| 7 | Single active VPN on Android | Android permits only one VPN at a time | Test firewall in isolation; do not run a second VPN on the device |
| 8 | Private DNS can override VPN DNS | Android system DoT resolver is independent of VpnService routes | Test Private DNS states explicitly; observe TCP 853 and resolver changes |
| 9 | Per-UID attribution on non-rooted devices is coarse | `dumpsys netstats` retention/granularity limits | UID tagging where available; aggregate at device level with stated confidence |
| 10 | Hyper-V alone cannot provide RF attacks | Virtual switches do not expose raw 802.11 | External AP or USB radio passed through to a Linux VM |
| 11 | UI not visually validated here | Headless Linux; no display | Functional controller + on-target visual pass |
| 12 | DHCP starvation/exhaustion can disrupt the lab | Inherently disruptive | Short duration, isolated VLAN, auto-recovery |
| 13 | Driver/adapter variance | OEM drivers gate AP/monitor/inject | Capability gating; coverage matrix downgrades unsupported rows |
| 14 | Cookie exposure cannot be confirmed without the device | Cookie values are only reported when present in captured plaintext traffic; this workspace has no Android device | Run the assessment on the Windows lab host with the authorized device browsing the synthetic sites |
| 15 | TLS interception is off by default | Installing a CA modifies the device and needs explicit consent | Separate opt-in experiment (`tests.allow_certificate_install_opt_in`) with its own report row |
| 16 | Session identity is not asserted | Correlated metadata can suggest patterns but cannot prove an authenticated identity | Report patterns with confidence; state plainly that identity was not established |
| 17 | Campaign stages stop without device evidence | A stage establishes its condition only from classifiable evidence | Documented as skipped stages with the unmet condition, never as success |

These limitations are enforced in code: capabilities, execution modes, and confidence
prevent a limitation from being reported as a capability.
