# Network Traffic and Connection Analysis

**Scope:** Using RouterOS counters, connection tracking, and interface statistics to identify anomalous traffic without capturing payloads.
**Last reviewed:** 2026-11-11
**Applies to:** RouterOS v6 and v7.

---

## 1. What RouterOS can and cannot tell you

| Question | RouterOS answer | Limitation |
|---|---|---|
| How much traffic now? | Interface rates, byte/packet counters | Snapshot or cumulative; no history |
| Who is talking to whom? | Connection table | Current connections only; expires |
| Which port? | Connection table, firewall counters | NAT can rewrite ports |
| How many connections? | `total-entries`, `count-only` | Snapshot; FastTrack may hide |
| Which protocol? | Connection `protocol` field | No payload |
| What is inside the traffic? | No | No native DPI/payload inspection |
| Was it malicious? | No direct answer | Requires correlation/threat intel |

RouterOS is a router with counters, not a flow collector. For historical analysis, use NetFlow/sFlow/IPFIX export or an external sensor. This skill must not start a packet capture or traffic generator.

---

## 2. Interface statistics

```ros
/interface/print stats
/interface/monitor-traffic interface=ether1 once
```

Expected shape:

```text
Columns: NAME, RX-BYTE, TX-BYTE, RX-PACKET, TX-PACKET, RX-DROP, TX-DROP
#   NAME    RX-BYTE     TX-BYTE     RX-PACKET  TX-PACKET  RX-DROP  TX-DROP
0 R ether1  842.1GiB    121.4GiB    912334221   183442110        0       12
1 R ether2  1.2TiB      903.2GiB    998112233   812004411        0        0
```

```text
    interface: ether1
        rx-rate: 912.4Mbps
        tx-rate: 88.1Mbps
   rx-packets-per-second: 148223
   tx-packets-per-second: 12044
```

Interpretation:

- `rx-rate` near the link speed means the uplink is saturated; router-side filtering cannot recover that bandwidth.
- High pps with low average packet size suggests small-packet flood, scan, or DNS/NTP amplification.
- `RX-DROP` rising can indicate saturation, but also cabling, duplex, or switch issues.
- Counters reset on reboot; record uptime with the sample.

Sampling discipline:

1. Take two samples at a known interval (for example 60 s).
2. Compute rate = (counter2 − counter1) / seconds.
3. Record time of day and known workloads.
4. Do not compare a peak minute to an average day.

---

## 3. Connection tracking

```ros
/ip/firewall/connection/tracking/print
/ip/firewall/connection/print count-only
/ip/firewall/connection/print where protocol=tcp
/ip/firewall/connection/print where dst-port=22
```

Expected connection fields:

| Field | Use |
|---|---|
| `protocol` | tcp, udp, icmp, other |
| `src-address`, `src-port` | Origin |
| `dst-address`, `dst-port` | Destination |
| `tcp-state` | `syn-sent`, `syn-recv`, `established`, `time-wait`, ... |
| `orig-packets`, `repl-packets` | Directional volume |
| `orig-bytes`, `repl-bytes` | Directional data |
| `timeout` | Remaining lifetime |
| `srcnat`, `dstnat` | NAT applied |
| `fasttrack` | Bypasses parts of the stack |
| `seen-reply` | Whether a reply was observed |
| `connection-mark` | Mangle mark, if any |

Patterns:

| Pattern | Possible meaning | Confounder |
|---|---|---|
| Many `syn-sent`, no reply | SYN scan or SYN flood | Broken upstream, busy NAT |
| Many established to one external IP:443 | Normal SaaS, or C2 over TLS | Need threat intel |
| One internal host to many external IPs:445 | Worm/lateral movement | Vulnerability scanner |
| Large `orig-bytes`, small `repl-bytes` | Upload/exfiltration | Backup, video upload |
| Large `repl-bytes`, small `orig-bytes` | Download | Updates, streaming |
| Many short-lived UDP flows | Scan, DNS, QUIC, VoIP | Legitimate app behavior |
| `total-entries` near `max-entries` | Connection exhaustion | NAT gateway scale |

Important: the connection table is a **snapshot**. A connection that closed is gone. You cannot reconstruct a full traffic history from it.

---

## 4. Firewall counters as traffic sensors

```ros
/ip/firewall/filter/print stats
/ip/firewall/raw/print stats
```

Use counters to answer:

- Are packets hitting the invalid/bogon drop rules?
- Is a rate-limit rule triggering?
- Is a blocklist rule seeing traffic?
- Is FastTrack handling most of the volume (dummy rule counters)?

Counters are cumulative since the last reset. They do not show source distribution or timing. A high count on a drop rule proves matches, not intent.

---

## 5. Queues and shaping data

```ros
/queue/simple/print
/queue/tree/print
/queue/type/print
```

Queues can show which internal hosts consume bandwidth. They are not a security control and can be bypassed by FastTrack. An unexpected queue can also shape or starve traffic.

---

## 6. Traffic pattern analysis

### 6.1 Baseline first

You cannot call traffic "abnormal" without a baseline. Collect, for the same time of day and day of week:

- average and peak bps;
- average and peak pps;
- dominant protocols/ports;
- number of active connections;
- top internal talkers (if flow data exists);
- CPU and conntrack usage.

Baselines can be manual samples or SNMP/graphing. RouterOS graphing is available on some devices; it is not a security tool.

### 6.2 Indicators of scanning/reconnaissance

- One source to many destination ports.
- Many destination hosts on one port.
- Short-lived connections with tiny byte counts.
- `syn-sent` bursts.
- Firewall drop counters rising.

### 6.3 Indicators of flooding

- pps or bps far above baseline.
- Dominance of one protocol (UDP, ICMP, TCP SYN).
- Conntrack growth.
- CPU/interrupt spikes.
- Rising input drops.
- Service unresponsiveness.

### 6.4 Indicators of unauthorized access

- Established management sessions (22/8291/8728/443) from unexpected sources.
- Long-lived sessions to management ports.
- New outbound connections after a login.
- Internal host contacting many peers on SMB/RDP/SSH/WinRM ports.

### 6.5 Indicators of C2/beaconing

- Repeated connections to the same rare destination at regular intervals.
- Small request/response sizes.
- Long-lived TLS sessions to a non-business destination.
- DNS queries at a fixed interval (needs DNS logging/flow, not native).
- Connections to ports not used by business applications.

RouterOS conntrack alone cannot prove beaconing; it lacks history. Use NetFlow or an IDS.

### 6.6 Indicators of exfiltration

- Sustained outbound bytes much larger than inbound for one host.
- Transfers outside business hours.
- Connections to cloud storage or unknown IPs.
- DNS/ICMP tunneling (payload-dependent; not native).

---

## 7. Unusual ports and destinations

Common legitimate ports:

| Port | Service |
|---|---|
| 22 | SSH |
| 25/465/587 | SMTP submission |
| 53 | DNS |
| 80/443 | HTTP/HTTPS |
| 123 | NTP |
| 389/636 | LDAP/LDAPS |
| 445 | SMB |
| 3389 | RDP |
| 8291 | WinBox |
| 8728/8729 | RouterOS API |

Unusual does not mean malicious. A non-standard port can be a legitimate application. Conversely, malware can use 443. Evaluate:

- Is the destination known and approved?
- Is the port consistent with the service?
- Is the traffic periodic?
- Is the volume consistent with the role?
- Does it correlate with a login or configuration change?

Do not rely on a static "bad port" list.

---

## 8. Sampling and performance

- Use `.proplist` to limit fields.
- Use `count-only` before pulling rows.
- Filter by address, port, protocol, or state.
- Cap rows and time.
- Avoid concurrent heavy reads.
- Do not run `torch`, `sniffer`, or packet capture in strict read-only mode.
- On a busy router, even a large `print` can affect CPU. Sample during a low-load window if possible.

---

## 9. Correlation checklist

When a traffic anomaly is found, correlate with:

- `/log/print` for logins, config changes, interface events.
- `/ip/firewall/filter/print stats` for rule matches.
- `/ip/firewall/address-list/print` for rate-limit entries.
- `/system/resource/print` for CPU/memory.
- `/ip/firewall/connection/tracking/print` for table pressure.
- `/ip/route/print` for routing changes.
- `/system/history/print` (v7) for who changed what.
- External flow/IDS/EDR data if available.

A traffic spike without a log entry is still a finding, but its cause may be unknown.

---

## 10. Reporting example

```text
Observation: ether1 received 912 Mbps and 148k pps for 6 minutes,
             versus a 90-day baseline of 120 Mbps and 18k pps.
Evidence:    /interface/monitor-traffic once; /interface/print stats;
             RX drops rising; conntrack total-entries rose from 18k to 210k.
Correlation: no login failures; no config changes; one UDP/53 outbound pattern.
Assessment:  high-volume flood consistent with a UDP/DNS amplification attempt.
             RouterOS alone cannot confirm source distribution or intent.
Impact:      uplink saturation; latency for all users; DNS resolution failures.
Confidence:  MEDIUM (single vantage point, no flow data).
Next steps:  obtain ISP/flow data; check whether the resolver is open to WAN;
             preserve logs; engage upstream filtering.
```

---

## 11. Detection limitations

- No payload inspection.
- No historical flows by default.
- Conntrack is a snapshot with short timeouts.
- NAT rewrites addresses and ports.
- FastTrack and hardware offload can bypass counters.
- Interface counters are cumulative and reset on reboot.
- Encrypted traffic hides content.
- A single vantage point cannot prove distribution.
- Sampling can miss short spikes.
- RouterOS graphing is not a security audit trail.

---

## 12. Sources

- Interface stats and monitor-traffic: <https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/interface-stats-and-monitor-traffic>
- Connection tracking: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/connection-tracking>
- Traffic flow: <https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/traffic-flow>
- Queues: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/queues>
- Packet flow: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/packet-flow-in-routeros>
- Torch (do not run in strict mode): <https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/torch>
- Packet sniffer (do not run in strict mode): <https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/packet-sniffer>
- MITRE ATT&CK T1046, T1071, T1041: <https://attack.mitre.org/>
