# Firewall Security Assessment

**Scope:** RouterOS filter, RAW, NAT, mangle, address lists, connection tracking, FastTrack, rule ordering, and the default firewall posture.
**Last reviewed:** 2026-11-11
**Applies to:** RouterOS v6.36+ and v7 (RAW requires 6.36+; v7 syntax is used unless noted).

---

## 1. Packet path in one page

A packet can take different paths depending on whether it is destined to the router, forwarded, bridged, or generated locally.

| Path | Chain(s) | Typical use |
|---|---|---|
| To the router | `input` | Management access, DNS/DHCP to the router, routing protocols. |
| Through the router | `forward` | LAN-to-WAN, WAN-to-LAN via dst-nat, inter-VLAN routing. |
| From the router | `output` | Router-originated traffic, updates, DNS queries, syslog. |
| Before conntrack | `raw` (`prerouting`, `output`) | Early drops, notrack, flood mitigation. |
| NAT | `srcnat`, `dstnat` | Address/port translation. |
| Marking | `mangle` (`prerouting`, `input`, `forward`, `output`, `postrouting`) | Packet/connection/routing marks, QoS. |
| Bridged | bridge filter / bridge NAT | Layer-2 forwarding; **does not use IP filter chains** by default. |

Critical consequences:

- A rule in `input` does not protect forwarded traffic.
- A rule in `forward` does not protect the router itself.
- Bridged traffic can bypass IP firewall entirely.
- FastTracked flows bypass filter, mangle, queues, and connection tracking after the first packets.

Official packet-flow reference: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/packet-flow-in-routeros>

---

## 2. Filter rules

### 2.1 Read the rules

```ros
/ip/firewall/filter/print
/ip/firewall/filter/print stats
/ipv6/firewall/filter/print
/ipv6/firewall/filter/print stats
```

Expected shape (synthetic):

```text
Flags: X - DISABLED; I - INVALID
Columns: CHAIN, ACTION, CONNECTION-STATE, IN-INTERFACE-LIST, COMMENT
 #   CHAIN    ACTION   CONNECTION-STATE              IN-INTERFACE-LIST  COMMENT
 0   input    accept   established,related,untracked                    defconf: accept established
 1   input    drop     invalid                                          defconf: drop invalid
 2   input    accept   icmp                                             defconf: accept ICMP
 3   input    drop                                                     defconf: drop all not from LAN
 4   forward  fasttrack-connection  established,related                defconf: fasttrack
 5   forward  accept   established,related,untracked                    defconf: accept established
 6   forward  drop     invalid                                          defconf: drop invalid
 7   forward  drop                                                     defconf: drop all from WAN not DSTNATed
```

`print stats` adds byte and packet counters:

```text
 #   CHAIN    ACTION   BYTES         PACKETS
 0   input    accept   50 507 925 242  50 048 246
 3   input    drop     432 270          9 719
```

### 2.2 Interpretation

- **Order matters.** The first terminating action wins. `log` and `passthrough` do not stop evaluation.
- A rule with **zero packets** may be unreachable, disabled, shadowed by an earlier rule, or bypassed by FastTrack. Do not conclude it is unnecessary without checking order.
- A **disabled** rule (`X`) has no effect, even if it looks correct.
- An **invalid** rule (`I`) references a missing object (interface, address list, chain) and is not doing what its text says.
- `accept` rules with `connection-state=established,related` are normal and desirable; they reduce load. They do not authorize new inbound sessions.
- A drop at the end of `input` is the difference between "default deny" and "default open".

### 2.3 Checks that catch real weaknesses

| Check | Command | Why it matters |
|---|---|---|
| Is there a final input drop? | `/ip/firewall/filter/print where chain=input` | Without it, the router accepts anything not explicitly dropped. |
| Is management restricted to LAN/VPN? | `/ip/firewall/filter/print where chain=input` | WAN-exposed WinBox/SSH/API/WebFig is the top compromise path. |
| Are WAN interfaces actually in the WAN list? | `/interface/list/member/print` | A rule matching `in-interface-list=WAN` protects nothing if membership is wrong. |
| Is IPv6 filtered? | `/ipv6/firewall/filter/print` | IPv6 is often forgotten; no NAT means hosts are directly reachable. |
| Are there broad accepts before drops? | `/ip/firewall/filter/print` | `action=accept` with no source restriction can shadow later drops. |
| Are critical rules disabled? | `/ip/firewall/filter/print` | An `X` flag on a drop rule is a silent hole. |
| Is FastTrack before security rules? | `/ip/firewall/filter/print` | FastTracked flows bypass later filter/mangle/queue processing. |
| Is invalid traffic dropped? | `/ip/firewall/filter/print where connection-state=invalid` | Invalid packets are a common scan/flood artifact. |
| Are logs enabled where needed? | `/ip/firewall/filter/print` | No `log=yes` means no firewall evidence. |

---

## 3. The default firewall (defconf)

MikroTik's default configuration is a reasonable baseline for a simple home/office router. It is **not** universal, and it is frequently removed or weakened.

The manual's advanced-firewall example uses these input rules:

```ros
/ip/firewall/filter
add action=accept chain=input comment="defconf: accept ICMP after RAW" protocol=icmp
add action=accept chain=input comment="defconf: accept established,related,untracked" connection-state=established,related,untracked
add action=drop chain=input comment="defconf: drop all not coming from LAN" in-interface-list=!LAN
```

And these forward rules:

```ros
/ip/firewall/filter
add action=fasttrack-connection chain=forward comment="defconf: fasttrack" connection-state=established,related
add action=accept chain=forward comment="defconf: accept established,related, untracked" connection-state=established,related,untracked
add action=drop chain=forward comment="defconf: drop invalid" connection-state=invalid
add action=drop chain=forward comment="defconf: drop all from WAN not DSTNATed" connection-nat-state=!dstnat connection-state=new in-interface-list=WAN
add action=drop chain=forward src-address-list=no_forward_ipv4 comment="defconf: drop bad forward IPs"
add action=drop chain=forward dst-address-list=no_forward_ipv4 comment="defconf: drop bad forward IPs"
```

Key properties of this baseline:

- The router is reachable from LAN, not from WAN.
- Established/related traffic is accepted early.
- Invalid traffic is dropped.
- WAN-to-LAN traffic must be explicitly destination-NATed.
- Bogon/non-forwardable addresses are dropped.
- FastTrack accelerates established flows, at the cost of bypassing later inspection.

What the baseline does **not** do:

- It does not protect a router whose WAN interface is not in the `WAN` list.
- It does not filter IPv6 unless the IPv6 rules are also present.
- It does not stop a compromised LAN host from attacking the router.
- It does not log most drops.
- It does not protect services explicitly opened to WAN.
- It does not survive an administrator adding a permissive rule above the drop.

---

## 4. RAW firewall

```ros
/ip/firewall/raw/print
/ip/firewall/raw/print stats
/ipv6/firewall/raw/print
```

Properties:

- Only two chains: `prerouting` and `output`.
- Runs **before** connection tracking.
- Cannot match `connection-state`, `connection-mark`, layer7, or other conntrack-dependent matchers.
- `action=notrack` excludes traffic from connection tracking.
- Useful for early drops and flood mitigation.

Example (do not apply in read-only mode):

```ros
/ip/firewall/raw
add chain=prerouting src-address-list=bad_src_ipv4 action=drop
```

Security review:

- Are bogon/martian source addresses dropped before conntrack?
- Is there a `notrack` rule that unintentionally bypasses stateful inspection?
- Are RAW drops logged? (Usually not, to save CPU. That is a visibility trade-off.)
- Does the RAW rule reference an address list that is still populated and correct?
- On v6, is the version at least 6.36? Older v6 has no RAW.

Limitations:

- RAW is stateless. It cannot distinguish a new connection from an established one.
- A RAW drop before conntrack also prevents NAT for that traffic.
- RAW cannot see the result of dst-nat because it runs before NAT.

---

## 5. NAT rules

```ros
/ip/firewall/nat/print
/ip/firewall/nat/print stats
```

Two directions:

- `chain=srcnat` — source NAT/masquerade, usually LAN to WAN.
- `chain=dstnat` — destination NAT/port forwarding, usually WAN to an internal service.

Security review:

| Check | Why it matters |
|---|---|
| Any `dstnat` to router management ports (22, 8291, 8728, 443, 80)? | Exposes the management plane. |
| Any `dstnat` to an internal host with no source restriction? | Exposes that host to the internet. |
| Any stale or disabled `dstnat` rules? | Disabled is safe now; stale enabled rules are forgotten exposure. |
| Any `dstnat` to an address that no longer exists? | Misconfiguration, possible hijack if the address is reused. |
| Is `masquerade` scoped to `out-interface-list=WAN`? | An unscoped masquerade can hide internal traffic unexpectedly. |
| Is UPnP enabled? | Applications can create dynamic dst-nat rules without review. |
| Is there a hairpin NAT rule? | Not a weakness, but it changes the apparent source. |
| Does the filter allow the forwarded port? | NAT does not bypass the forward chain for new connections. |

Expected shape:

```text
Flags: X - DISABLED; I - INVALID
Columns: CHAIN, ACTION, PROTOCOL, DST-PORT, TO-ADDRESSES, COMMENT
 #   CHAIN   ACTION     PROTOCOL  DST-PORT  TO-ADDRESSES   COMMENT
 0   srcnat  masquerade                                    
 1   dstnat  dst-nat    tcp       443       192.168.88.20  web server
```

Interpretation:

- Rule 1 exposes 192.168.88.20:443 to anyone who can reach the router's WAN address. That may be intentional. The finding is not "port forward exists"; it is "port forward is unnecessary / unrestricted / to a sensitive host".
- NAT does not log by default. Add logging only through a change process.

---

## 6. Mangle rules

```ros
/ip/firewall/mangle/print
/ip/firewall/mangle/print stats
```

Mangle marks packets, connections, and routing decisions. It is not primarily a security control, but it can be abused:

- A routing mark can redirect traffic to an attacker-controlled gateway.
- A packet mark can change queue behavior or policy routing.
- A `change-ttl` or `change-mss` rule can break or fingerprint traffic.
- A mangle rule that accepts/marks before a security rule can alter the path.

Review for unexpected marks, routing marks, and `action=accept`/`drop` in mangle (unusual). Correlate with `/ip/route/print` and `/routing/rule/print` (v7).

---

## 7. Address lists

```ros
/ip/firewall/address-list/print
/ip/firewall/address-list/print where list~"blacklist|ddos|bruteforce"
```

Properties:

- Static entries are administrator-defined.
- Dynamic entries are added by firewall rules, DNS resolution, or scripts, often with a timeout.
- Entries have a creation time and remaining timeout.

Security review:

- A dynamic entry is **not proof of an attack**; it may be a false positive from a rate limit.
- A static entry with no comment or owner is a documentation and hygiene risk.
- A very large list can consume memory and slow rule matching.
- An attacker who can add to an address list (via a script or API) can block legitimate users.
- A list named `blacklist` that is not referenced by any rule does nothing.

Expected shape:

```text
Flags: D - DYNAMIC
Columns: LIST, ADDRESS, TIMEOUT, CREATION-TIME
#   LIST        ADDRESS         TIMEOUT  CREATION-TIME
0 D ddos-attackers 203.0.113.45  9m12s    2026-11-11 14:02:11
1   allow-admin 192.0.2.0/24           2026-10-01 09:00:00
```

---

## 8. Connection tracking and stateful inspection

```ros
/ip/firewall/connection/tracking/print
/ip/firewall/connection/print count-only
/ip/firewall/connection/print where dst-port=22
```

States:

- `new` — first packet of a connection.
- `established` — belongs to an existing connection.
- `related` — related to an existing connection (ICMP errors, FTP data).
- `invalid` — not part of a valid connection; should usually be dropped.
- `untracked` — bypassed conntrack via RAW.

Review:

- Is `connection-state=invalid` dropped in input and forward?
- Is `loose-tcp-tracking` enabled? It is the default and can treat mid-stream packets as established.
- Is the conntrack table near `max-entries`? That is a resource-exhaustion indicator, not proof of DDoS.
- Are there many short-lived `syn-sent` entries? Possible scan or SYN flood, but also a busy NAT gateway.

Expected shape:

```text
[admin@edge-rtr] > /ip/firewall/connection/tracking/print
        enabled: auto
      max-entries: 1048576
    total-entries: 18422
```

---

## 9. FastTrack

FastTrack is an optimization, not a security feature. Once a connection is fasttracked:

- filter rules after the FastTrack rule do not see its packets;
- mangle rules do not see them;
- simple queues and some queue trees do not shape them;
- connection tracking does not update normally.

Security consequences:

- A drop rule added after FastTrack does not stop an existing fasttracked connection.
- Traffic analysis based on filter counters can undercount.
- Malicious traffic that is fasttracked early may evade later inspection.

Review:

```ros
/ip/firewall/filter/print where action=fasttrack-connection
```

Ask: is FastTrack placed after the rules that must always see traffic (for example, a blocklist drop)? If not, the blocklist may be ineffective for established flows.

---

## 10. Rule-ordering anti-patterns

| Anti-pattern | Why it is dangerous |
|---|---|
| `accept` all from LAN before a drop | A compromised LAN host has full access to the router. |
| `drop` after an `accept` with no match criteria | The drop is unreachable. |
| Disabled drop rule left in place | Gives a false sense of protection. |
| `in-interface=ether1` instead of `in-interface-list=WAN` | Breaks when the WAN interface changes (PPPoE, LTE, failover). |
| No final drop | Default-open router. |
| IPv4 rules only | IPv6 hosts are unfiltered. |
| `src-address=0.0.0.0/0` on an accept rule | No restriction. |
| Logging every dropped packet during a flood | CPU exhaustion; the logging becomes the DoS. |
| `connection-state=established,related` accepted without `invalid` drop | Invalid packets continue to be processed. |

---

## 11. Findings and severity guidance

| Finding | Typical severity | Notes |
|---|---|---|
| No input drop / router reachable from WAN | CRITICAL | Confirm with service exposure; do not rely on rule text alone. |
| WinBox/SSH/API/WebFig open to WAN | CRITICAL | Even with a strong password, exploitation surface is high. |
| Known exploited RouterOS CVE applicable + service exposed | CRITICAL | Verify version and advisory. |
| Missing IPv6 filter with IPv6 enabled | HIGH | Direct reachability, no NAT. |
| No invalid-state drop | MEDIUM | Depends on other rules. |
| Unrestricted dst-nat to a sensitive host | HIGH | Depends on the host and service. |
| Open DNS resolver | HIGH | Amplification abuse. |
| UPnP enabled | MEDIUM | Dynamic exposure, depends on environment. |
| No firewall logging / no remote syslog | MEDIUM | Visibility gap, not an attack. |
| FastTrack before blocklist | MEDIUM | Existing flows bypass the block. |
| Stale/disabled rules | LOW | Hygiene, unless the disabled rule was the only control. |
| No comments on rules | INFO | Maintainability. |

Do not assign CRITICAL based only on a rule's appearance. Establish exposure: is the interface reachable from an untrusted network? Is the service actually listening?

---

## 12. Defensive recommendations (do not apply automatically)

1. Keep a default-deny input chain and a default-deny forward chain.
2. Put management access behind a VPN (WireGuard) and close WinBox/SSH/API/WebFig on WAN.
3. Restrict services with both firewall rules and `available-from`.
4. Filter IPv6 with the same rigor as IPv4.
5. Drop invalid traffic early in input and forward.
6. Scope NAT to the WAN interface list and review every dst-nat.
7. Disable UPnP, SOCKS, web proxy, and unused packages.
8. Do not expose the DNS resolver to untrusted networks.
9. Log selectively, with `log-prefix`, and ship logs to a remote syslog/SIEM.
10. Place FastTrack after rules that must always inspect traffic.
11. Document every rule with a comment and an owner.
12. Review the firewall after every upgrade or topology change.

All changes require a maintenance window, a rollback plan, and out-of-band access. This skill must not perform them.

---

## 13. Detection limitations

- Firewall logs exist only where logging is configured.
- Logging every drop during a flood can overload the CPU; absence of logs during an attack is expected.
- FastTrack and hardware offload can hide packets from counters.
- NAT hides internal sources.
- Bridged traffic bypasses IP firewall.
- Rule counters are cumulative since the last reset; they do not show timing.
- A disabled rule still appears in `print`, which can mislead a reader.
- `print stats` shows matches, not unique sources or destinations.

---

## 14. Sources

- Firewall overview: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall>
- Filter: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall/filter>
- RAW (inside Filter): <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall/filter#raw-filtering>
- NAT: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall/nat>
- Mangle: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall/mangle>
- Address lists: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall/address-lists>
- Connection tracking: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/connection-tracking>
- Packet flow: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/packet-flow-in-routeros>
- Building advanced firewall (defconf rules): <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/user-guides/building-advanced-firewall>
- Common matchers and actions: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall/common-firewall-matchers-and-actions>
- Securing your router: <https://manual.mikrotik.com/docs/getting-started/securing-your-router>
