# 06 — Android Firewall Integration Assessment

## 1. Supported evaluation architectures

### 1.1 VPNService-based firewall
- **Detect:** `adb shell dumpsys connectivity` (VPN network, `NetworkAgentInfo`),
  `adb shell dumpsys vpn` (where present), `settings get global always_on_vpn_app`,
  `appops get <pkg> ACTIVATE_VPN`.
- **Observe:** routes in `adb shell ip route show table all`, IPv6 in `ip -6 route`,
  DNS via `dumpsys connectivity | grep -i dns`, per-UID tagging via `dumpsys netstats`.
- **Known weaknesses tested:** missing IPv6 route (`::/0`), DNS leak during tunnel setup,
  Private DNS override, `protect()` loop, single-active-VPN constraint.

### 1.2 Root / iptables-nft based firewall
- **Detect:** presence of `iptables-legacy`/`nft` rules, per-UID chains, firewall package.
- **Observe:** `iptables -L -n -v -x` / `nft list ruleset`, `dumpsys netstats`, logcat.
- **Constraint:** requires root; results only valid on rooted test devices.

### 1.3 Private DNS / DoT-only control
- **Detect:** `settings get global private_dns_mode`, `private_dns_specifier`.
- **Observe:** TCP 853 flows, resolver reachability.
- **Constraint:** domain-only; not an IP firewall; tests are limited to DNS policy.

### 1.4 Firewall app with local API/logs
- Pluggable adapter interface (`FirewallTelemetryAdapter`) to ingest JSON/log lines.
- No concrete vendor is assumed; the interface and a file-log adapter are provided.

## 2. Observation strategy (defense in depth)

1. **Primary independent evidence:** Npcap capture on the lab network. This observes what
   actually crossed the wire, independent of firewall claims.
2. **Corroborating evidence:** lab server logs (DNS/DHCP/HTTP/TLS), host telemetry.
3. **Device-side evidence:** ADB dumpsys/logcat, when available.
4. **Firewall-reported evidence:** only if a telemetry adapter exists; always labeled as
   self-reported and never sufficient alone for a PASS.

If internal decisions are invisible, the platform states `Confidence.LOW/MEDIUM` and the
verdict is `PARTIALLY_VERIFIED` unless an independent source confirms the block.

## 3. Device identification

- USB serial / `ro.serialno`, `ro.product.model`, `ro.build.version.release/sdk`,
  `ro.build.fingerprint`, security patch level.
- Network identity: MAC (with randomization caveat), DHCP client hostname, assigned IP.
- Firewall identity: package name, version (`dumpsys package`), always-on state, lockdown.

## 4. Clock synchronization

- Read `adb shell date +%s.%N` and host UTC; compute skew; store in session metadata.
- Correlate events using session-relative monotonic time plus absolute UTC with skew
  adjustment. Report skew magnitude; warn if > 2 s.

## 5. Safety on the device

- No APK installation or modification by default.
- Permission revocation / process kill tests are opt-in and clearly labeled.
- All device-side commands are logged with their exact invocation in evidence.
