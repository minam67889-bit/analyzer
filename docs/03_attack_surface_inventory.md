# 03 — Attack Surface Inventory

Each row: technique, preconditions, primary observables, impact, lab feasibility, mapping.
"Feasibility" is `HIGH` (lab can do it end-to-end), `MED` (needs specific hardware/adapter),
`LOW` (external dependency or OS restriction), `NA` (not applicable to this subject).

## A. Wireless infrastructure

| ID | Technique | Preconditions | Observables | Impact | Feasibility | Mapping |
|---|---|---|---|---|---|---|
| W-01 | Open/WPA2/WPA3 lab AP onboarding | AP control | association, DHCP, DHCP options | baseline | HIGH | — |
| W-02 | Rogue AP / evil twin (SSID clone) | second radio or external AP | probe/assoc to rogue BSSID | interception | MED | T1557.004 |
| W-03 | BSSID cloning | adapter allows spoofed TX | client assoc to rogue BSSID | interception | MED | T1557.004 |
| W-04 | Deauthentication flood | monitor/inject adapter | deauth frames, reconnect cycles | DoS / forced roam | MED | T1498 |
| W-05 | Disassociation flood | monitor/inject adapter | disassoc frames | DoS | MED | T1498 |
| W-06 | PMF downgrade (WPA3→WPA2) | AP supports both | association security flags | weaker mgmt protection | MED | T1562 |
| W-07 | KARMA / probe-response AP | monitor/inject or external AP | probe requests, auto-assoc | interception | MED | T1557.004 |
| W-08 | Captive portal clone | lab web server | HTTP requests, form posts | credential capture | HIGH | T1185 |
| W-09 | AP isolation / client isolation toggle | AP control | client↔client reachability | segmentation test | HIGH | T1503 |
| W-10 | Channel/roam manipulation | AP control | BSS transition events | transition test | HIGH | T1563 |

## B. Layer 2

| ID | Technique | Preconditions | Observables | Impact | Feasibility | Mapping |
|---|---|---|---|---|---|---|
| L2-01 | ARP spoofing/poisoning | on-path position | gratuitous ARP, MAC flips | interception/DoS | HIGH | T1557.002 |
| L2-02 | MAC impersonation (gateway/AP) | TX injection | frames with spoofed SA | interception | MED | T1557 |
| L2-03 | DHCP rogue server | on-path | DHCPOFFER/ACK from rogue | config injection | HIGH | T1557.003 |
| L2-04 | DHCP option manipulation (DNS/gateway) | lab DHCP | lease options | misconfiguration | HIGH | T1557.003 |
| L2-05 | DHCP starvation | L2 access | exhausted pool | DoS | HIGH | T1498 |
| L2-06 | Broadcast/multicast exposure | capture | mDNS/LLMNR/NBNS traffic | discovery leakage | HIGH | T1557.001 |
| L2-07 | VLAN/segmentation bypass | managed switch/AP | cross-VLAN reachability | isolation break | LOW | T1599 |
| L2-08 | STP/LLDP manipulation | managed switch | topology changes | interception | LOW | T1556 |

## C. Layer 3

| ID | Technique | Preconditions | Observables | Impact | Feasibility | Mapping |
|---|---|---|---|---|---|---|
| L3-01 | Default gateway manipulation | DHCP/RA | route table | interception | HIGH | T1557 |
| L3-02 | Static route injection | on-path | unexpected routes | interception | HIGH | T1030 |
| L3-03 | ICMP redirect | on-path, same subnet | ICMP type 5 | route change | MED | T1557 |
| L3-04 | RA injection / rogue router | IPv6 | RA, default route v6 | interception | MED | T1557 |
| L3-05 | SLAAC address selection | IPv6 | addresses, DAD | dual-stack behavior | MED | T1059 |
| L3-06 | DHCPv6 manipulation | IPv6 | DHCPv6 msgs | config injection | MED | T1557.003 |
| L3-07 | IPv6 bypass of IPv4 firewall | dual-stack | v6-only flows | policy bypass | HIGH | T1065 |
| L3-08 | Split-tunnel route test | VPN firewall | routes inside/outside | leak | HIGH | T1557 |
| L3-09 | Unexpected interface/transport | device state | new network handles | policy bypass | HIGH | T1422 |

## D. DNS

| ID | Technique | Preconditions | Observables | Impact | Feasibility | Mapping |
|---|---|---|---|---|---|---|
| D-01 | DNS spoofing (authoritative answer) | rogue resolver | mismatched answer | redirect | HIGH | T1557 |
| D-02 | DNS poisoning (cache) | resolver control | poisoned cache | redirect | HIGH | T1557 |
| D-03 | DNS hijack (resolver switch) | DHCP/RA/DoT | resolver change | redirect | HIGH | T1557 |
| D-04 | DNS rebinding | short-TTL zone | public→private switch | SOP bypass | HIGH | T1557 |
| D-05 | DNS leak to underlying network | VPN firewall | queries outside tunnel | privacy | HIGH | T1557 |
| D-06 | DNS fallback behavior | resolver fail | fallback resolver | privacy | HIGH | T1557 |
| D-07 | DNS cache behavior | repeat queries | cache hits/TTL | inference | HIGH | T1040 |
| D-08 | DNSSEC validation downgrade | lab zone | DO/AD bits | integrity | MED | T1557 |
| D-09 | DoH endpoint steering | DoH client | 443 to DoH host | bypass | HIGH | T1572 |
| D-10 | DoT endpoint steering | DoT client | TCP 853 | bypass | HIGH | T1572 |
| D-11 | DoQ endpoint steering | DoQ client | UDP 853 QUIC | bypass | MED | T1572 |
| D-12 | Malformed DNS responses | rogue resolver | parser errors | app behavior | HIGH | T1499 |
| D-13 | Conflicting split answers | multiple resolvers | differing A/AAAA | inconsistency | HIGH | T1557 |
| D-14 | DNS timeout/blackhole | drop policy | timeouts | DoS | HIGH | T1498 |
| D-15 | DNS tunneling indicators | allowed DNS | high-entropy labels | exfil | HIGH | T1071.004 |

## E. Transport

| ID | Technique | Preconditions | Observables | Impact | Feasibility | Mapping |
|---|---|---|---|---|---|---|
| T-01 | TCP connect to lab sink | lab server | SYN/SYN-ACK/ACK | permit/block | HIGH | — |
| T-02 | UDP to lab sink | lab server | datagrams | permit/block | HIGH | — |
| T-03 | Connection reset injection | on-path | RST | session kill | HIGH | T1498 |
| T-04 | Port filtering matrix | lab servers | per-port outcome | policy | HIGH | T1562 |
| T-05 | Fragmentation/MTU/PMTU | path MTU change | fragments, ICMP PTB | behavior | MED | T1498 |
| T-06 | Connection exhaustion | lab server | backlog/state | DoS | HIGH | T1499 |
| T-07 | State tracking inconsistency | mid-stream reset | stale flow behavior | bypass | MED | T1562 |

## F. Application / web

| ID | Technique | Preconditions | Observables | Impact | Feasibility | Mapping |
|---|---|---|---|---|---|---|
| A-01 | Plain HTTP to lab endpoint | lab web | request metadata | cleartext | HIGH | T1040 |
| A-02 | HTTPS with lab CA | lab TLS | handshake, trust | cert validation | HIGH | T1557 |
| A-03 | HTTPS with wrong hostname | lab TLS | alert | hostname check | HIGH | T1557 |
| A-04 | Expired/self-signed cert | lab TLS | alert | validation | HIGH | T1557 |
| A-05 | TLS version/cipher downgrade | lab TLS | negotiated params | weak crypto | HIGH | T1562 |
| A-06 | HSTS/redirect handling | lab web | redirect chain | downgrade | HIGH | T1185 |
| A-07 | Proxy behavior | lab proxy | proxy CONNECT | interception | HIGH | T1090 |
| A-08 | WebSocket endpoint | lab WS | upgrade frames | protocol | HIGH | T1102 |
| A-09 | WebRTC/local candidate exposure | browser | SDP/candidates | IP leak | MED | T1557 |
| A-10 | HTTP/2 and HTTP/3 behavior | lab server | ALPN, QUIC | protocol | HIGH | T1102 |
| A-11 | Cookie/session attributes | lab web | Set-Cookie flags | session | HIGH | T1539 |
| A-12 | Certificate pinning | lab TLS | handshake failure | pinning | HIGH | MASVS-NETWORK-2 |

## G. Mobile-specific

| ID | Technique | Preconditions | Observables | Impact | Feasibility | Mapping |
|---|---|---|---|---|---|---|
| M-01 | VPNService tunnel continuity | VPN firewall | tun state, routes | continuity | HIGH | T1557 |
| M-02 | Per-app allow/deny enforcement | per-app rules | UID-tagged flows | policy | HIGH | T1562 |
| M-03 | Background app traffic | app in background | traffic timing | policy | HIGH | T1562 |
| M-04 | Always-on VPN / lockdown | system settings | lockdown state | enforcement | HIGH | T1562 |
| M-05 | VPN reconnect behavior | toggle | reconnect time | leak window | HIGH | T1557 |
| M-06 | Fail-open vs fail-closed | kill VPN service | traffic without VPN | leak | HIGH | T1562 |
| M-07 | IPv6 bypass | dual-stack | v6 flows | leak | HIGH | T1065 |
| M-08 | DNS bypass | VPN DNS config | resolver path | leak | HIGH | T1557 |
| M-09 | Wi-Fi↔cellular transition | device radios | network switch | continuity | HIGH | T1422 |
| M-10 | Multiple active interfaces | dual transport | chosen route | leak | HIGH | T1557 |
| M-11 | Battery optimization effect | doze | deferred traffic | policy | MED | T1464 |
| M-12 | Firewall permission revocation | ADB | service state | enforcement | HIGH | T1562 |
| M-13 | Firewall process death | ADB kill | service restart | enforcement | HIGH | T1562 |
| M-14 | Private DNS override | DoT | resolver selection | leak | HIGH | T1557 |

## H. Adversary workflow coverage

Recon → positioning → infrastructure manipulation → observation → redirection →
impersonation → protocol manipulation → persistence of condition → recovery test →
evidence correlation. The test catalog maps each stage to at least one scenario and each
scenario to one or more ATT&CK/OWASP IDs.
