# 12 — Research Bibliography

All URLs were retrieved during the research phase (2026-11). Publication/version data is
as stated by the source. "Relevance" explains how the source constrains the implementation.

## Microsoft / Windows

| # | Source | Version / date | URL | Implementation relevance |
|---|---|---|---|---|
| W1 | WFP Architecture Overview (Microsoft Learn) | retrieved 2026-11 | https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-architecture-overview | Defines user/kernel filtering layers, BFE, callout drivers; bounds what WFP can do without a kernel driver |
| W2 | Windows Filtering Platform (Wikipedia) | retrieved 2026-11 | https://en.wikipedia.org/wiki/Windows_Filtering_Platform | Confirms MAC-layer filtering since Win8, vSwitch filtering, per-app filters, weights/sublayers |
| W3 | Windows.Networking.NetworkOperators namespace (Microsoft Learn) | win32/winrt-22621 | https://learn.microsoft.com/en-us/uwp/api/Windows.Networking.NetworkOperators | API surface for `NetworkOperatorTetheringManager`, tethering client and AP configuration |
| W4 | Enable Windows hotspot via PowerShell/WinRT (Stack Overflow) | 2017, still canonical | https://stackoverflow.com/questions/45833873/enable-windows-10-built-in-hotspot-by-cmd-batch-powershell | Concrete WinRT invocation pattern used by the PowerShell bridge |
| W5 | LanSpot — WinRT hotspot control project | retrieved 2026-11 | https://github.com/toe-dot-tech/LanSpot | Independent confirmation that WinRT, not netsh, is the correct hotspot API on modern hardware |
| W6 | How to create a Wi-Fi AP on Windows 10 (WOSHub) | retrieved 2026-11 | https://woshub.com/how-to-create-a-wi-fi-access-point-on-windows-10/ | Distinguishes hosted network vs Mobile Hotspot; driver capability caveats |
| W7 | Mobile Hotspot vs netsh hosted network (ITechGuides) | retrieved 2026-11 | https://www.itechguides.com/how-to-disable-or-enable-mobile-hotspot-in-windows-11-10-tutorial/ | Confirms modern hotspot uses Wi-Fi Direct/tethering, not `netsh wlan` |
| W8 | "We can't set up mobile hotspot" (Microsoft Q&A) | 2018 | https://learn.microsoft.com/en-us/answers/questions/2814830/we-cant-set-up-mobile-hotspot-cant-set-up-hostedne | Real `netsh wlan show wirelesscapabilities` output showing Soft AP / monitor mode support flags |
| W9 | Npcap vs libpcap vs WinPcap (OpenPCB) | retrieved 2026-11 | https://www.openpcap.com/pcap/libpcap-winpcap-npcap | Npcap is NDIS 6 LWF, WinPcap-compatible, maintained; WinPcap deprecated/unpatched |
| W10 | Scapy Installation & Troubleshooting (scapy.readthedocs.io) | Scapy 2.8.0 docs | https://scapy.readthedocs.io/en/latest/installation.html ; https://scapy.readthedocs.io/en/latest/troubleshooting.html | Npcap requirement, `monitor=True`, raw 802.11 caveats and known bad npcap versions |

## Android

| # | Source | Version / date | URL | Implementation relevance |
|---|---|---|---|---|
| A1 | `VpnService.Builder` API reference (Android Developers) | retrieved 2026-11 | https://developer.android.com/reference/android/net/VpnService.Builder | `addAllowedApplication`, `addDisallowedApplication` (mutually exclusive), `addRoute`, `addDnsServer`, `setUnderlyingNetworks`, `allowBypass` |
| A2 | `VpnService` API reference (Android Developers) | retrieved 2026-11 | https://developer.android.com/reference/android/net/VpnService | `protect()` semantics (prevent VPN loop), `setUnderlyingNetworks` |
| A3 | Split Tunneling in VPN Apps (digitaldtech) | 2026-11 | https://digitaldtech.com/blog/split-tunneling-vpn-apps/ | Per-app vs route rules, Android 13 `excludeRoute`, LAN exemption, domain-rule absence |
| A4 | DNS traffic can leak outside the VPN tunnel (Mullvad / GrapheneOS) | 2024-2025 | https://github.com/GrapheneOS/os-issue-tracker/issues/5273 | Tunnel-setup leak windows; Private DNS leak; informs leak tests and timing |
| A5 | How to prevent DNS leaks (Mullvad) | retrieved 2026-11 | https://mullvad.net/en/help/dns-leaks | Private DNS strict-mode override, per-OEM behaviors |
| A6 | Android Private DNS setup guide (encapsulated.network) | 2026-11 | https://encapsulated.network/vpn-android-setup/ | Private DNS vs VPN DNS interaction |
| A7 | NetValve — VpnService per-app controller (GitHub) | retrieved 2026-11 | https://github.com/meilide38/NetValve | Example userspace netstack architecture; IPv6 handling modes |
| A8 | fosrl/android issue #42 — IPv6-only DNS hole | 2026-08 | https://github.com/fosrl/android/issues/42 | VpnService IPv6 blackhole / protect() requirement; concrete failure evidence |

## Protocols & standards

| # | Source | Version / date | URL | Implementation relevance |
|---|---|---|---|---|
| P1 | RFC 7858 — DNS over TLS | 2016-05 | https://datatracker.ietf.org/doc/html/rfc7858 | DoT transport on TCP 853; observable as dedicated-port TLS |
| P2 | RFC 8484 — DNS Queries over HTTPS | 2018-10 | https://datatracker.ietf.org/doc/html/rfc8484 | DoH on 443; blends with web traffic; limits DNS metadata inference |
| P3 | RFC 9250 — DNS over QUIC | 2022-05 | https://datatracker.ietf.org/doc/html/rfc9250 | DoQ on UDP 853; QUIC-based encrypted DNS |
| P4 | RFC 8446 — TLS 1.3 | 2018-08 | https://datatracker.ietf.org/doc/html/rfc8446 | Handshake metadata, encrypted SNI context |
| P5 | RFC 9114 — HTTP/3 | 2022-06 | https://datatracker.ietf.org/doc/html/rfc9114 | HTTP over QUIC; protocol identification |
| P6 | RFC 9000 — QUIC | 2021-05 | https://datatracker.ietf.org/doc/html/rfc9000 | QUIC long/short header; connection migration |
| P7 | RFC 8499 — DNS Terminology | 2019-01 | https://datatracker.ietf.org/doc/html/rfc8499 | Terminology for resolver/authoritative distinction |
| P8 | IEEE 802.11w-2009 — Protected Management Frames | 2009 | https://standards.ieee.org/ieee/802.11w/ | Deauth/disassoc protection via MIC/IGTK/BIP |

## Security frameworks

| # | Source | Version / date | URL | Implementation relevance |
|---|---|---|---|---|
| S1 | MITRE ATT&CK T1557 Adversary-in-the-Middle | v17, retrieved 2026-11 | https://attack.mitre.org/versions/v17/techniques/T1557/ | Sub-techniques T1557.001 LLMNR/NBT-NS, T1557.002 ARP cache poisoning, T1557.003 DHCP spoofing, T1557.004 evil twin |
| S2 | MITRE ATT&CK T1498 Network DoS / T1565.002 Transmitted Data Manipulation | retrieved 2026-11 | https://attack.mitre.org/techniques/T1498/ ; https://attack.mitre.org/techniques/T1565/002/ | Deauth DoS and on-path modification mappings |
| S3 | OWASP MASVS-NETWORK checklist | June 2025 | https://mas.owasp.org/checklists/MASVS-NETWORK/ | MASVS-NETWORK-1/2 controls; test IDs |
| S4 | OWASP MASTG-TEST-0242 Missing Certificate Pinning | retrieved 2026-11 | https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0242/ | Pinning test method; scope rules (first-party domains) |
| S5 | OWASP MASTG-NETWORK overview (SecPortal) | retrieved 2026-11 | https://secportal.io/frameworks/owasp-mastg | Test procedure manual structure; version declaration expectations |
| S6 | NIST SP 800-153 — Guidelines for Secure Wireless LAN | 2012 (cited) | https://csrc.nist.gov/publications/detail/sp/800-153/final | Rogue AP / wireless DoS guidance |
| S7 | Protecting Browsers from DNS Rebinding Attacks (Jackson et al., ACM) | 2009 | https://dl.acm.org/doi/pdf/10.1145/1462148.1462150 | DNS rebinding/SOP bypass theory and defenses |
| S8 | State of DNS Rebinding (DEF CON 27, Doussot/Meyer) | 2019 | https://media.defcon.org/DEF%20CON%2027/DEF%20CON%2027/presentations/DEFCON-27-Gerald-Doussot-Roger-Meyer-State-of-DNS-Rebinding-Attack-and-Prevention-Techniques-and-the-Singularity-of-Origin.pdf | Rebinding bypasses: 0.0.0.0, CNAME, localhost |
| S9 | What Is DNS Rebinding (Palo Alto Unit 42 / Cyberpedia) | 2025-10 | https://www.paloaltonetworks.com/cyberpedia/what-is-dns-rebinding | Rebinding impact incl. CSRF token theft |
| S10 | Wi-Fi Deauth Attacks & 802.11w (pwnsy) | 2026-07 | http://blog.pwnsy.com/wifi-deauth-attacks-explained | Deauth mechanics, detection signals, ATT&CK mapping |
| S11 | Evil Twin Access Points (Hive Security) | 2026-08 | https://hivesecurity.gitbook.io/blog/evil-twin-access-points-wifi-attack/ | Evil-twin chain, PMF, captive portal cloning |
| S12 | Man-in-the-Middle on Wi-Fi (it-learn.io) | 2026-04 | https://blog.it-learn.io/posts/2026-04-28-evil-twin-wifi-man-in-the-attack/ | Full chain: rogue AP, PMKID, deauth, interception |

## Open-source components evaluated

| Component | Verdict |
|---|---|
| Npcap | Adopted as capture backend; raw 802.11 option |
| Wireshark/TShark | Adopted as optional machine-readable analyzer (JSON/fields export) |
| Scapy | Adopted for packet craft/inject and optional deep parse; pure-Python PCAP reader kept for evidence |
| NetValve (VpnService controller) | Studied as architecture reference, not vendored |
| LanSpot | Studied for WinRT hotspot control pattern |
| dnsmasq / Technitium / CoreDNS | Evaluated; a built-in minimal DNS/DHCP server is used for reproducibility and zero external deps |

## Explicitly rejected / not used

- **WinPcap**: deprecated, NDIS 5, unpatched since 2013, DLL hijack risk. Replaced by Npcap.
- **netsh hostednetwork as primary AP**: wrong API for modern hotspot; kept only as a capability-probing fallback.
- **Full TLS MITM by default**: out of scope for third-party endpoints and unnecessary for firewall evaluation; lab-only test trust is supported instead.
