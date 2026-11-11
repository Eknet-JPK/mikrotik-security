# DoS and DDoS Detection and Triage

**Scope:** Recognizing floods, amplification, and resource exhaustion from RouterOS evidence, and distinguishing them from legitimate load.
**Last reviewed:** 2026-11-11
**Applies to:** RouterOS v6 and v7.

---

## 1. Definitions

- **DoS (Denial of Service)** — an attack from one source or a small set of sources that degrades or stops a service.
- **DDoS (Distributed Denial of Service)** — an attack from many distributed sources, often a botnet.
- **Volumetric attack** — saturates bandwidth (UDP flood, DNS amplification, ICMP flood).
- **Protocol/state-exhaustion attack** — consumes connection tables, sockets, or CPU (SYN flood, connection exhaustion).
- **Application-layer attack** — exhausts an application with seemingly valid requests (HTTP flood, slowloris).

RouterOS can observe what reaches the router and what the router forwards. It cannot see attack traffic that is dropped upstream, and it cannot prove intent or botnet distribution by itself.

Relevant MITRE ATT&CK:

- T1498 — Network Denial of Service
- T1498.001 — Direct Network Flood
- T1498.002 — Reflection Amplification
- T1499 — Endpoint Denial of Service

---

## 2. First question: is the router the target or the path?

| Scenario | What saturates | RouterOS symptoms |
|---|---|---|
| Router's own service (SSH, WinBox, DNS, VPN) | Router CPU/socket table | High CPU, auth logs, conntrack to router, service unresponsive |
| A host behind the router (port-forwarded) | Forward path / host | High forward counters, conntrack to the host, host unreachable |
| The uplink itself | ISP link | Interface rx near line rate, packet loss, high latency, router CPU may be low |
| The router's control plane | CPU/interrupts | High CPU, slow CLI, routing protocol flaps |
| A DNS resolver | Outbound bandwidth + CPU | Large UDP/53 responses, high pps, open resolver config |

The distinction changes the recommendation. Upstream saturation must be filtered by the ISP; router firewall rules cannot recover bandwidth already consumed.

---

## 3. Evidence collection (read-only)

### 3.1 Interface counters

```ros
/interface/print stats
/interface/monitor-traffic interface=ether1 once
```

Expected shape:

```text
[admin@edge-rtr] > /interface/print stats
Flags: R - RUNNING
Columns: NAME, RX-BYTE, TX-BYTE, RX-PACKET, TX-PACKET, RX-DROP, TX-DROP
#   NAME    RX-BYTE     TX-BYTE     RX-PACKET  TX-PACKET  RX-DROP  TX-DROP
0 R ether1  842.1GiB    121.4GiB    912334221   183442110        0       12
1 R ether2  1.2TiB      903.2GiB    998112233   812004411        0        0
```

`monitor-traffic ... once` gives a rate sample:

```text
    interface: ether1
        rx-rate: 912.4Mbps
        tx-rate: 88.1Mbps
   rx-packets-per-second: 148223
   tx-packets-per-second: 12044
```

Interpretation:

- Compare with the link speed and the normal baseline. 912 Mbps on a 1 Gbps link is near saturation.
- Very high pps with low average packet size suggests a flood or scan.
- Rising `RX-DROP` supports saturation, but drops can also come from bad cables, duplex mismatch, or switch issues.
- Counters are cumulative; two samples over time are better than one.

### 3.2 CPU, memory, and conntrack

```ros
/system/resource/print
/ip/firewall/connection/tracking/print
/ip/firewall/connection/print count-only
```

Expected shape:

```text
        enabled: auto
      max-entries: 1048576
    total-entries: 918223
```

Interpretation:

- `total-entries` close to `max-entries` indicates connection-table pressure.
- High CPU with low throughput can indicate small-packet flood, conntrack churn, or logging load.
- Falling free memory with a stable configuration can indicate conntrack growth, queues, or a leak.

### 3.3 Firewall and RAW counters

```ros
/ip/firewall/filter/print stats
/ip/firewall/raw/print stats
```

Look for:

- Drop counters rising rapidly on invalid/bogon/flood rules.
- The FastTrack dummy rule counters (they show fasttracked traffic separately).
- A RAW drop rule doing most of the work (good for CPU).
- No counters at all (rules not matching, disabled, or traffic not reaching them).

### 3.4 Address lists created by defensive rules

```ros
/ip/firewall/address-list/print where list~"ddos|blacklist"
```

MikroTik's official DDoS example creates `ddos-targets` and `ddos-attackers` with a 10-minute timeout, using `dst-limit=32,32,src-and-dst-addresses/10s`. Entries are evidence that the rate condition was exceeded, not proof of a DDoS.

### 3.5 Logs

```ros
/log/print where topics~"error|critical|firewall"
```

Useful entries:

- Interface link up/down (a flood can cause link flaps or resets).
- Firewall log entries with a flood prefix.
- `login failure` bursts (attack on management).
- Out-of-memory or conntrack errors (message text varies by version).
- Watchdog reboots (after the fact).

### 3.6 DNS-specific evidence

```ros
/ip/dns/print
/ip/firewall/filter/print where dst-port=53
/ip/firewall/connection/print where dst-port=53
```

If `allow-remote-requests=yes` and port 53 is reachable from WAN, the router may be an open resolver and a reflection source. Large outbound UDP/53 responses are a red flag.

---

## 4. Attack signatures

| Type | Primary signature | Secondary evidence | Confounders |
|---|---|---|---|
| SYN flood | High new TCP SYN rate; many `syn-sent`/`syn-recv`; conntrack growth | CPU up, input drops, service slow | Busy NAT, monitoring, load test |
| UDP flood | High pps, mostly UDP, small packets | Conntrack churn, CPU, uplink saturation | QUIC, VoIP, DNS, video |
| ICMP flood | High pps, protocol 1 | CPU, input drops | Network monitoring, ping tests |
| DNS amplification | Inbound UDP/53 to an open resolver; large outbound responses to victims | High tx on WAN, spoofed sources, resolver enabled | Legitimate DNS server load |
| NTP/SSDP/memcached amplification | Inbound requests to exposed UDP services | Large outbound responses | Misconfigured services |
| Connection exhaustion | `total-entries` near `max-entries`; new connections fail | Invalid packets, CPU, memory | NAT gateway with many clients |
| HTTP flood | Many new TCP connections to 80/443, established sessions | Host CPU/app load, not router CPU | Flash crowd, crawlers |
| Slowloris | Many half-open HTTP connections | Host/app exhaustion | Slow clients |
| Resource exhaustion | CPU/memory saturated by a process | Profiler, logs | Crypto, queues, logging, bug |

---

## 5. Is it a DDoS?

A defensible conclusion needs more than one number.

**Can say "consistent with a flood" when:**

- Interface rate/pps is far above baseline for the same time of day.
- The traffic is concentrated on a protocol/port/service.
- CPU or conntrack is under pressure.
- Multiple independent counters agree.
- The condition started abruptly and correlates with user reports.

**Can say "DDoS" with higher confidence when:**

- External flow data or ISP data shows many sources.
- The source distribution is wide and spoofed.
- The target is a specific service and the pattern matches a known reflection/amplification vector.
- The attack is sustained and not explained by a legitimate event.

**Cannot say "DDoS" from:**

- A single interface graph.
- High CPU alone.
- A full conntrack table alone.
- One firewall log line.
- An old RouterOS version.

Use: "indicates a high-volume flood consistent with a DoS attempt; distribution cannot be confirmed from RouterOS alone."

---

## 6. Distinguishing attack from legitimate load

Check:

- Time of day and known events (backup, update window, live stream, exam, promotion).
- Whether the traffic is inbound to one service or broadly distributed.
- Whether the source addresses are diverse and short-lived.
- Whether the payload/protocol matches a reflection vector.
- Whether the router or a host is the bottleneck.
- Whether the condition stops when a specific rule/host is isolated (do not do this in read-only mode; recommend it).
- Whether a new device, misconfiguration, or routing loop was introduced.

A misconfigured queue, a routing loop, or a broken NIC can look like a flood. Rule those out.

---

## 7. Impact assessment

Assess:

- **Availability** — users disconnected, services unreachable, routing adjacencies down.
- **Control plane** — CLI/WinBox slow, routing flaps, SNMP timeouts.
- **State** — conntrack exhaustion, NAT failures, DHCP starvation.
- **Collateral** — upstream link saturation affects other sites; reflection attacks can get the ISP to block you.
- **Evidence** — logs may be lost if the router reboots or the buffer rotates.
- **Recovery** — time to restore, whether a reboot is required, whether config changed.

---

## 8. Recommendations (do not apply automatically)

Immediate (owner/ISP action):

1. Engage the ISP/uplink provider for upstream filtering or scrubbing.
2. If the router is an open resolver, close port 53 from WAN.
3. Disable unused UDP services (NTP server, SSDP/UPnP, memcached-like services if any).
4. Rate-limit new connections per source/destination (MikroTik `dst-limit` pattern).
5. Enable SYN cookies for the router's own TCP services (`/ip/settings/set tcp-syncookies=yes`) — a change, not this skill.
6. Drop invalid and bogon traffic early in RAW.
7. Protect management services behind a VPN.
8. Preserve logs and capture evidence before rebooting.

Structural:

- BCP38/BCP84 ingress filtering at the ISP.
- DDoS scrubbing or anycast.
- Redundant uplinks and out-of-band management.
- Capacity planning and baseline monitoring.
- NetFlow/sFlow to a collector.
- Alerting on pps, conntrack, and CPU thresholds.

Never recommend "block the source IP" as the only response to a distributed attack; it does not scale and can block legitimate users.

---

## 9. Detection limitations

- RouterOS cannot see traffic filtered upstream.
- FastTrack and hardware offload may bypass counters.
- Interface counters are cumulative and may reset.
- Conntrack is a snapshot with short timeouts.
- Spoofed sources make attribution unreliable.
- NAT obscures internal sources.
- Logging during a flood can worsen CPU load.
- `monitor-traffic` is a sample, not a capture.
- A reboot destroys volatile evidence.
- The router cannot distinguish a botnet from a flash crowd without external data.

---

## 10. Sources

- DDoS protection (official): <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/user-guides/ddos-protection>
- Interface stats and monitor-traffic: <https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/interface-stats-and-monitor-traffic>
- Connection tracking: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/connection-tracking>
- IP settings (SYN cookies, rp-filter): <https://manual.mikrotik.com/docs/cli-reference/ip/settings>
- RAW filtering: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall/filter#raw-filtering>
- DNS: <https://manual.mikrotik.com/docs/network-management/dns>
- MITRE ATT&CK T1498: <https://attack.mitre.org/techniques/T1498/>
- MITRE ATT&CK T1499: <https://attack.mitre.org/techniques/T1499/>
- CISA DDoS guidance: <https://www.cisa.gov/>
