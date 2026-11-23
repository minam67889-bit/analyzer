# 02 — Independent Threat Model

## 1. Scope and assumptions

- **Actor:** authorized lab operator; **subject:** the mobile firewall on the authorized
  Android device; **adversary role:** the lab controller emulating an attacker on the
  laboratory network.
- **Trust boundaries:** (T1) Android device ↔ lab AP; (T2) lab AP ↔ lab services;
  (T3) lab services ↔ controller; (T4) controller ↔ Windows host network stack;
  (T5) lab network ↔ external internet (must remain denied or tightly controlled).
- **Out of scope:** attacking unrelated clients, third-party infrastructure, or any
  non-authorized device; decrypting TLS payloads of third parties.

## 2. Adversary model

The emulated adversary is a **local network attacker with radio proximity** and, in some
profiles, **infrastructure control**. This is deliberately stronger than a remote attacker
because the laboratory can legitimately stand up rogue infrastructure.

Adversary capabilities (configurable per profile):

| Capability | Realized by |
|---|---|
| Radio transmission | Second adapter in monitor/injection mode or external AP |
| Rogue AP / evil twin | External AP or lab AP with cloned SSID/BSSID |
| DHCP server | Lab DHCP component / rogue responder |
| DNS server / authority | Lab DNS component with configurable zone and TTL |
| On-path L2 | ARP spoofing / gateway impersonation |
| On-path L3 | RA injection, route manipulation, ICMP redirect (where valid) |
| HTTP/TLS endpoint | Lab web/TLS servers with lab-controlled certificates |
| Traffic observation | Npcap capture + parsers |
| Disruption | Deauth/disassoc, port/connection resets, blackholes |
| Persistence | Sustained conditions until explicitly recovered |

## 3. Attack chains

### Chain A — Rogue infrastructure onboarding
1. Stand up rogue AP with same SSID (and optionally same BSSID) as the lab network.
2. Force a reconnect (deauth) or wait for roaming.
3. Serve DHCP with attacker DNS/gateway.
4. Observe whether the firewall permits the new path and whether DNS is controlled.

### Chain B — Resolution manipulation
1. Device performs a lookup for a lab-owned name.
2. Adversary answers with a lab-owned IP that hosts a TLS endpoint with an untrusted
   certificate (or a plain-HTTP endpoint).
3. Observe whether the firewall blocks/alerts, whether the OS/app rejects the cert, or
   whether traffic flows.
4. Repeat with rebinding (public→private), CNAME-to-localhost, and 0.0.0.0 answers.

### Chain C — Gateway/route manipulation
1. Introduce a second gateway via DHCP/RA or ARP.
2. Observe the device's chosen route and whether protected traffic leaves via the
   unexpected path.
3. Reclaim the original route and test recovery.

### Chain D — Firewall-state stress
1. Toggle firewall/VPN state (reconnect, network switch Wi-Fi↔cellular, airplane mode,
   permission revocation via ADB) while a connection is in flight.
2. Observe fail-open vs fail-closed behavior and tunnel-setup leak windows.
3. Restore and verify recovery.

### Chain E — Encrypted-DNS bypass
1. Configure DoT/DoH/DoQ endpoints.
2. Attempt to steer the device's resolver outside the firewall's visibility.
3. Observe resolver selection, Private DNS interaction, and any plaintext fallback.

## 4. Observable indicators

| Indicator | Source | Meaning |
|---|---|---|
| SYN with no SYN-ACK | capture | blocked, filtered, or unreachable |
| RST from device-side | capture | host/firewall rejected |
| DNS answer mismatch | DNS server log | spoof took effect |
| TLS handshake failure/alert | TLS server + capture | certificate/validation rejection |
| App-level error | ADB logcat | application rejection (not firewall) |
| Connection success to lab sink | server log | permitted |
| Route/RA change | host/device telemetry | network reconfiguration |
| VPN interface state | ADB dumpsys | tunnel continuity |
| Deauth frames | capture | L2 disruption occurred |

## 5. Verdict discipline

A missing packet is not proof of detection. A connection failure is not proof of a
firewall block. Every verdict requires at least one primary observation plus, where
available, a corroborating source, and is tagged with a `BlockCause` and `Confidence`.
`INCONCLUSIVE` is an acceptable and expected outcome for tests where telemetry is
insufficient.

## 6. Safety invariants (enforced in code)

1. Active injection targets only the configured device MAC/IP and lab-owned endpoints.
2. The lab network denies or tightly controls egress during active phases.
3. Any configuration change is recorded and rolled back by the recovery manager.
4. Emergency stop halts all injectors, restores routes/DNS/DHCP, and stops the hotspot.
5. Evidence is append-only and hash-chained per session.
