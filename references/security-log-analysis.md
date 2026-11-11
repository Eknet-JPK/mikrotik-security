# Security Log Analysis

**Scope:** Reading, filtering, correlating, and reporting RouterOS logs for security investigations.
**Last reviewed:** 2026-11-11
**Applies to:** RouterOS v6 and v7. Field availability and formats differ; see section 10.

---

## 1. How RouterOS logging works

Two menus control logging:

- `/system/logging` — rules that select entries by topic and send them to an action.
- `/system/logging/action` — destinations: memory, disk, echo (console), remote syslog, email, or script.

Default behavior (per the current manual):

| Topic | Action | Result |
|---|---|---|
| `info` | memory | Kept in RAM |
| `error` | memory | Kept in RAM |
| `warning` | memory | Kept in RAM |
| `critical` | echo | Printed on open terminals, and at next login |

The memory action keeps the newest **1000** entries by default, and they are lost on reboot. Debug messages are not logged by default. To keep history, configure disk logging or a remote syslog server — a change the router owner must make.

```ros
/system/logging/print
/system/logging/action/print
/log/print
```

Security interpretation:

- If there is no `remote` action with a real server address, log retention is probably poor.
- If only `info`/`error`/`warning` are logged, debug-level authentication details are missing.
- If the `critical` action is only `echo`, failed logins may not persist after the terminal closes.
- A logging configuration that sends everything to memory during a flood can push out the evidence you need.

---

## 2. Topics that matter for security

| Topic | Content | Use |
|---|---|---|
| `account` | User logins and logouts | Who accessed the router, from where, via which service. |
| `system` + `info` | Configuration changes, item added/changed | Who changed what. |
| `system` + `error` + `critical` | Failed logins, critical errors | Brute force, service failures. |
| `firewall` | Entries from firewall `action=log` | Dropped/accepted packets, scans, floods. |
| `dhcp` | Leases, assignments, deassignments | Rogue DHCP symptoms, lease churn. |
| `dns` | Resolver events | DNS failures, cache/adlist issues (not per-query by default). |
| `ppp`, `l2tp`, `pptp`, `ovpn`, `ipsec`, `wireguard` | VPN/PPP events | Remote-access abuse, tunnel failures. |
| `wireless` | Wireless client events | Association floods, authentication failures. |
| `interface` | Link up/down | Outages, flapping, physical tampering. |
| `script` | Script output | Unexpected automation. |
| `critical` | Events needing attention | Failed logins, watchdog reboots, clock changes. |
| `warning` | Warnings | Resource pressure, misconfiguration. |
| `error` | Errors | Service failures, resource exhaustion. |

Topics are additive: `system,error,critical` is one entry with three topics. A rule matches only entries that have **all** listed topics (and none of the excluded `!topics`).

---

## 3. Log line anatomy

```text
14:22:51 system,error,critical login failure for user admin from 203.0.113.45 via ssh
```

| Part | Meaning |
|---|---|
| `14:22:51` | Time (date omitted if the entry is from today) |
| `system,error,critical` | Topics |
| `login failure ...` | Message |

Configuration-change example:

```text
14:33:02 system,info firewall rule added by admin
```

Firewall log example:

```text
14:02:11 firewall,info INPUT-SCAN input: in:ether1 out:(none), src-mac 00:00:5E:00:53:45,
    proto TCP, 203.0.113.45:51515->192.0.2.1:22, len 60
```

A firewall `log` action records in/out interface, source MAC, protocol, source IP:port, destination IP:port, and packet length. It does not include TCP flags; the rule's `log-prefix` identifies the condition.

v7 `with-extra-info`:

```ros
/log/print with-extra-info where message~"login failure"
```

```text
14:22:51 system,error,critical login failure for user admin from 203.0.113.45 via ssh
    app=ssh duser=admin outcome=failure src=203.0.113.45
```

The structured fields are more reliable than parsing the message text.

---

## 4. Time handling

RouterOS log timestamps are tricky:

- Entries from **today** may show only `HH:MM:SS`.
- Older entries show `mon/dd HH:MM:SS` without a year.
- The year is implicit; around New Year, ordering can be ambiguous.
- The router's time zone and clock accuracy determine the meaning of every timestamp.
- Remote syslog may use BSD time without a year or time zone unless configured otherwise.

Before building a timeline:

```ros
/system/clock/print
/system/ntp/client/print
```

Record the router's time zone, clock, and NTP sync state. If the clock is wrong, say so; do not silently "correct" timestamps in the report.

---

## 5. Query patterns

### 5.1 Failed logins

```ros
/log/print where message~"login failure"
/log/print where topics~"critical" and message~"login"
```

### 5.2 Successful logins and logouts

```ros
/log/print where topics~"account"
/log/print where message~"logged in"
/log/print where message~"logged out"
```

### 5.3 Configuration changes

```ros
/log/print where topics~"system" and message~" by "
```

### 5.4 Time window

```ros
/log/print where time>"2026-11-11 00:00:00" and time<"2026-11-11 06:00:00"
```

### 5.5 Firewall events by prefix

```ros
/log/print where topics~"firewall" and message~"SCAN"
/log/print where topics~"firewall" and message~"DROP"
```

### 5.6 Interface and system events

```ros
/log/print where topics~"interface"
/log/print where topics~"system" and message~"reboot"
```

### 5.7 Follow new entries

```ros
/log/print follow-only where topics~"critical"
```

`follow` prints existing entries first; `follow-only` prints new ones. Both stream until interrupted. In strict read-only mode, prefer a finite snapshot; do not leave a streaming command running unattended.

### 5.8 Saving logs

Do **not** use `/log print file=...`: it writes a file on the router and is prohibited in read-only mode. Export logs through an existing syslog/SIEM pipeline or ask the owner to retrieve them.

---

## 6. Correlation method

### Step 1 — Normalize

Parse each line into:

```text
timestamp | topics | message | source | destination | service | user | outcome
```

Use `with-extra-info` on v7 where available. On v6, extract `from <ip>` and `via <service>` with a strict parser.

### Step 2 — Group

Group by:

- source IP;
- username;
- service;
- event type (failure, success, config change, firewall drop);
- 1-minute or 5-minute buckets.

### Step 3 — Build a timeline

```text
02:11:04  failure  ssh     admin      203.0.113.45
02:11:07  failure  ssh     root       203.0.113.45
...
02:29:31  failure  ssh     oracle     203.0.113.45   (412th failure)
02:31:19  success  ssh     admin      203.0.113.45
02:33:02  change   system  admin      user svc-backup added
02:34:10  change   system  admin      firewall rule added
02:35:44  change   system  admin      script added
02:40:12  conn     tcp     router     198.51.100.99:443
```

### Step 4 — Pivot

For each suspicious source:

```ros
/log/print where message~"203.0.113.45"
/ip/firewall/address-list/print where address=203.0.113.45
/ip/firewall/connection/print where src-address=203.0.113.45
```

For each suspicious user:

```ros
/user/print where name=admin
/log/print where message~"admin"
/system/history/print
```

### Step 5 — Check for evidence gaps

- Did the router reboot during the window?
- Was the log cleared?
- Was the buffer full?
- Was remote syslog configured?
- Did the clock jump?
- Did the attacker disable logging?

A gap is a finding in itself.

---

## 7. Event interpretation

| Event | Benign explanation | Suspicious explanation |
|---|---|---|
| `login failure` | Typo, stale saved password | Brute force, spraying, credential stuffing |
| `login success` | Admin working | Unauthorized access, credential theft |
| `firewall rule added` | Change ticket | Persistence, opening a backdoor |
| `user added` | Onboarding | Backdoor account |
| `script added` | Automation | Persistence, data collection |
| `scheduler added` | Maintenance | Persistence, beaconing |
| `interface link down` | Cable, ISP | Physical tampering, flood-induced reset |
| `reboot` | Upgrade, power | Crash, watchdog, attacker reboot |
| `DHCP lease` | New device | Rogue DHCP, starvation |
| `wireless deauth` | Roaming | Deauth attack, interference |
| `firewall drop` | Scan, misconfiguration | Targeted attack, flood |

Never treat one event as proof. Look for sequences and independent corroboration.

---

## 8. Log source integrity

An attacker with admin access can:

- clear memory logs;
- remove logging rules;
- change the remote syslog target;
- reboot the router;
- disable logging.

Therefore:

- Prefer remote syslog/SIEM with append-only retention.
- Record the router's uptime; a recent reboot may explain missing logs.
- Compare `/system/history` (v7) with log entries.
- Check for logging configuration changes in the log itself.
- Preserve external evidence before remediation.

This skill must not clear, modify, or export logs in a way that alters the router.

---

## 9. Common false positives

- Multiple memory/disk actions causing duplicate entries.
- `follow` output containing old entries.
- Time-zone mismatch between router and SIEM.
- NAT making many clients look like one source.
- A vulnerability scanner authorized by the owner.
- A monitoring tool with a stale password.
- A scheduled script that logs at `info`.
- A DHCP server with a short lease time causing churn.
- A wireless controller with many roaming events.

Check context before escalating.

---

## 10. Version differences

| Feature | v6 | v7 |
|---|---|---|
| Default memory buffer | ~1000 entries | ~1000 entries |
| `with-extra-info` | Not on older v6 | Yes |
| CEF remote format | No | 7.18+ |
| `remote-protocol` TCP/TLS | Limited | Yes (CEF for TCP/TLS) |
| Separate memory buffers | Limited | Yes |
| `/system/history` | No | Yes |
| Log topics | Fewer | More (container, wireguard, etc.) |

If a query returns nothing, check whether the field or option exists on that version before concluding there were no events.

---

## 11. Reporting the log analysis

Include:

- data source (memory, disk, syslog, SIEM);
- retention window and buffer size;
- time zone and clock accuracy;
- query strings used;
- counts, not just examples;
- first/last seen per source;
- known gaps;
- confidence level.

Example:

```text
Source: router memory log (default 1000-entry buffer), no remote syslog.
Window: 2026-11-11 00:00–06:00 (Asia/Bangkok), clock synchronized via NTP.
Finding: 412 failed SSH logins from 203.0.113.45 between 02:11:04 and 02:29:31,
         targeting 37 usernames, followed by a successful admin login at 02:31:19.
Confidence: HIGH for the failure pattern; MEDIUM for unauthorized access
            (the admin login has not been confirmed as legitimate or illegitimate).
Gap: no logs before 00:00; buffer may have rotated.
```

---

## 12. Sources

- Log: <https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log>
- Log CLI reference: <https://manual.mikrotik.com/docs/cli-reference/log>
- Monitoring and troubleshooting: <https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting>
- User policies: <https://manual.mikrotik.com/docs/authentication-authorization-accounting/user>
- Securing your router: <https://manual.mikrotik.com/docs/getting-started/securing-your-router>
- MITRE ATT&CK (log-related techniques): <https://attack.mitre.org/>
- NIST CSF 2.0 Detect: <https://www.nist.gov/cyberframework>
