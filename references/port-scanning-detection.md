# Port Scanning and Service Enumeration Detection

**Scope:** Recognizing reconnaissance against RouterOS devices and networks, using RouterOS-native evidence.
**Last reviewed:** 2026-11-11
**Applies to:** RouterOS v6 and v7.

---

## 1. Scan types and what they look like

| Scan | Technique | RouterOS-visible artifact |
|---|---|---|
| TCP connect | Full handshake to each port | Established/short connections, firewall accept/log rules |
| TCP SYN ("half-open") | SYN, waits for SYN-ACK/RST, never completes | `syn-sent` conntrack entries, SYN log rules |
| FIN/NULL/XMAS | Unusual flag combinations | Filter/drop counters; often no log unless configured |
| ACK scan | ACK without handshake | `invalid` state, filter drops |
| UDP scan | UDP probes, ICMP port unreachable | UDP conntrack entries, ICMP type 3 code 3 |
| Service enumeration | Banner grabs, version probes | Application logs, IDS, not native RouterOS |
| Network discovery | ARP, ICMP, mDNS, LLDP, MNDP, SSDP | Neighbor/ARP tables, broadcast traffic counters |
| Horizontal scan | Same port across many hosts | Forward-chain logs, NetFlow |
| Vertical scan | Many ports on one host | Input/forward logs, conntrack |

RouterOS is a router, not an IDS. It does not classify scans by itself. Detection depends on what you configured to log, count, or add to an address list.

Relevant MITRE ATT&CK:

- T1046 — Network Service Discovery
- T1595 — Active Scanning
- T1590 — Gather Victim Network Information
- T1018 — Remote System Discovery

---

## 2. What RouterOS can show

### 2.1 Firewall log entries

A firewall rule with `action=log` produces entries like:

```text
14:02:11 firewall,info INPUT-SCAN input: in:ether1 out:(none), src-mac 00:00:5E:00:53:45,
    proto TCP, 203.0.113.45:51515->192.0.2.1:22, len 60
```

The official firewall `log` action records: in-interface, out-interface, source MAC, protocol, source IP:port, destination IP:port, and packet length. It does **not** include TCP flags in the message. The rule's `log-prefix` is how you know which condition matched.

Example detection rules (recommendations only — do not apply in read-only mode):

```ros
/ip/firewall/filter
add chain=input action=log log-prefix="SCAN-SYN" protocol=tcp tcp-flags=syn,!ack connection-state=new \
    comment="log new inbound SYNs"
add chain=forward action=log log-prefix="SCAN-FWD" protocol=tcp tcp-flags=syn,!ack connection-state=new \
    comment="log new forwarded SYNs"
```

Warnings:

- Logging every SYN can overwhelm the CPU and the log buffer during a scan or flood.
- Place logging rules carefully; `action=log` continues to the next rule, so it does not block traffic.
- Prefer rate-limited address-list detection over logging every packet on a busy edge router.

### 2.2 Connection tracking

```ros
/ip/firewall/connection/print where protocol=tcp
/ip/firewall/connection/print where tcp-state=syn-sent
/ip/firewall/connection/print count-only
```

Expected shape (synthetic):

```text
Flags: S - seen-reply, A - assured
Columns: PROTOCOL, SRC-ADDRESS, DST-ADDRESS, TCP-STATE, TIMEOUT
#   PROTOCOL  SRC-ADDRESS          DST-ADDRESS          TCP-STATE  TIMEOUT
0   tcp       198.51.100.88:51222  192.0.2.1:22         syn-sent   4s
1   tcp       198.51.100.88:51223  192.0.2.1:23         syn-sent   4s
2   tcp       198.51.100.88:51224  192.0.2.1:80         syn-sent   4s
```

Useful fields: `src-address`, `src-port`, `dst-address`, `dst-port`, `tcp-state`, `timeout`, `orig-packets`, `repl-packets`.

Patterns:

- Many `syn-sent` entries from one source to many destination ports.
- Many entries with tiny packet counts and short timeouts.
- One source touching ports 21, 22, 23, 80, 443, 8291, 8728 in sequence.

Limitations:

- Conntrack is a snapshot. Entries expire quickly (SYN timeout is short).
- FastTracked connections may not appear as expected.
- A busy NAT gateway produces many legitimate short connections.

### 2.3 Firewall counters

```ros
/ip/firewall/filter/print stats
/ip/firewall/raw/print stats
```

A drop rule with a rising packet count is evidence that traffic matched the rule. It does not identify the source. Combine with logs or address lists.

### 2.4 Address lists

```ros
/ip/firewall/address-list/print where list~"scan|blacklist|ddos"
```

If a defensive rule adds scanners to a list, the entries show source addresses, creation time, and remaining timeout. This is stronger evidence than a single log line because it reflects a rate condition.

### 2.5 ARP and neighbor tables

```ros
/ip/arp/print
/ip/neighbor/print
```

A sudden population of the ARP/neighbor table can indicate discovery, but it can also be normal DHCP churn or a new segment. RouterOS neighbor discovery (MNDP/CDP/LLDP) is for management, not security monitoring.

---

## 3. Analysis method

### Step 1 — Establish the observation window

Record the log buffer range, the remote syslog retention, and the time zone. A scan that lasted 40 seconds may be invisible in a 1000-entry buffer if the router is busy.

### Step 2 — Normalize and group

For each candidate source, compute:

- number of distinct destination ports;
- number of distinct destination hosts;
- time between first and last event;
- TCP flags/state if available;
- whether any connection succeeded;
- whether authentication attempts followed.

Illustrative synthetic summary:

| Source | Distinct ports | Distinct hosts | Window | Followed by auth failures? |
|---|---:|---:|---|---|
| 203.0.113.45 | 1,024 | 1 | 38 s | Yes, 12 SSH failures |
| 198.51.100.23 | 18 | 1 | 2 s | No |
| 192.0.2.77 | 1 | 64 | 5 min | No |

Interpretation:

- Row 1 is a vertical scan followed by authentication attempts: targeted reconnaissance, high concern.
- Row 2 touches 18 ports quickly: likely a scan, but could be a browser or monitoring probe. Check the ports and source.
- Row 3 is horizontal discovery of many hosts on one port: could be legitimate inventory or worm-like propagation. Needs context.

### Step 3 — Correlate with authentication and configuration events

```ros
/log/print where message~"login failure"
/log/print where topics~"system" and message~" by "
```

A scan followed by failed logins is a strong targeted-attack pattern. A scan with no follow-up is reconnaissance.

### Step 4 — Check whether the scan succeeded

Look for:

- `connection-state=established` entries to the scanned ports;
- application logs (SSH, WinBox, API, WebFig);
- new users, scripts, schedulers, firewall rules;
- changes in `/system/history` (v7).

A port being open is not a compromise. A successful login after a scan is a much stronger signal.

---

## 4. Heuristic thresholds

These are analysis heuristics, not RouterOS defaults:

| Pattern | Heuristic | Confidence |
|---|---|---|
| Vertical TCP scan | ≥20 distinct dst ports from one source in ≤60 s | MEDIUM/HIGH |
| Horizontal scan | ≥10 distinct dst hosts on one port in ≤5 min | MEDIUM |
| Stealth scan | Many `invalid`/RST events, few established | LOW/MEDIUM without packet capture |
| UDP scan | Many UDP probes + ICMP port unreachable | MEDIUM |
| Scan + auth attempts | Scan followed by ≥3 login failures within 30 min | HIGH for targeted attack |
| Authorized scanner | Source in an approved scanner list, scheduled window | NORMAL (verify authorization) |

Always report raw counts and the window.

---

## 5. False positives

- Authorized vulnerability scanners and asset inventory tools.
- Monitoring systems checking many ports.
- Browsers and applications opening multiple ports (Happy Eyeballs, WebRTC, QUIC).
- Backup software, mail clients, and P2P applications.
- Port knocking sequences (intentional, but looks like a scan).
- NAT gateways aggregating many users.
- DHCP churn or new devices populating ARP/neighbor tables.
- Security tools on the LAN that scan by design.

Verify authorization and source ownership before calling a scan malicious.

---

## 6. Detection limitations

- **No native IDS.** RouterOS does not label scans.
- **No logging by default.** Most dropped packets are silent.
- **Log volume.** Logging scans can cause CPU/log exhaustion; attackers can exploit this.
- **Short conntrack timeouts.** SYN entries disappear quickly.
- **Spoofed sources.** UDP scans can spoof; TCP scans generally need a routable source to complete a handshake.
- **NAT.** Many internal scanners can appear as one public address.
- **IPv6.** Scans may target IPv6, which is often unfiltered.
- **FastTrack.** Established flows may bypass counters.
- **Distributed scans.** Each source stays below thresholds.
- **Encrypted protocols.** Payload-based enumeration is invisible.

---

## 7. Defensive recommendations

1. Default-deny input and forward; drop invalid states.
2. Close unused services (`telnet`, `ftp`, `www`, `api` if unused).
3. Restrict management to LAN/VPN and `available-from`.
4. Log selectively with prefixes, and ship logs off-box.
5. Use address-list rate limiting for repeat offenders.
6. Use port knocking where appropriate, but understand it is not authentication.
7. Deploy NetFlow/sFlow or an IDS for real scan detection.
8. Monitor IPv6 with the same rules as IPv4.
9. Keep an inventory of authorized scanners and their source addresses.
10. Alert on "scan followed by auth failure" rather than on scans alone.

This skill must not apply these changes. Provide them as a prioritized plan.

---

## 8. Sources

- Filter and logging action: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall/filter>
- Connection tracking: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/connection-tracking>
- Log: <https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log>
- Address lists: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall/address-lists>
- DDoS protection (rate-based lists): <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/user-guides/ddos-protection>
- MITRE ATT&CK T1046: <https://attack.mitre.org/techniques/T1046/>
- MITRE ATT&CK T1595: <https://attack.mitre.org/techniques/T1595/>
- NIST CSF 2.0 Detect: <https://www.nist.gov/cyberframework>
