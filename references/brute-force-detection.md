# Brute-Force Detection and Analysis

**Scope:** Detecting and assessing password-guessing attacks against RouterOS management and VPN services.
**Last reviewed:** 2026-11-11
**Applies to:** RouterOS v6 and v7. Log field availability differs; see section 3.

---

## 1. What counts as brute force

Brute force is repeated authentication attempts against an account or service. Variants:

| Variant | Pattern | Typical target |
|---|---|---|
| Classic brute force | Many passwords, one username | SSH, WinBox, API, FTP, WebFig |
| Password spraying | One/few passwords, many usernames | Exposed management services |
| Credential stuffing | Known leaked username/password pairs | VPN, WebFig, API |
| Slow/low-and-slow | A few attempts per hour, spread out | Any service, to evade rate limits |
| Distributed | Many source IPs, few attempts each | Internet-facing services |

Relevant MITRE ATT&CK techniques:

- T1110 — Brute Force
- T1078 — Valid Accounts
- T1133 — External Remote Services
- T1021.004 — Remote Services: SSH

---

## 2. RouterOS authentication logging

### 2.1 Failed login

A failed login produces an entry with the topics `system,error,critical`:

```text
14:22:51 system,error,critical login failure for user admin from 203.0.113.45 via ssh
```

On v7, `with-extra-info` adds structured fields:

```ros
/log/print with-extra-info where message~"login failure"
```

```text
14:22:51 system,error,critical login failure for user admin from 203.0.113.45 via ssh
    app=ssh duser=admin outcome=failure src=203.0.113.45
```

Fields:

| Field | Meaning |
|---|---|
| `app` | Service (`ssh`, `winbox`, `api`, `web`, `ftp`, `telnet`, `ppp`, ...) |
| `duser` | Destination username attempted |
| `outcome` | `failure` or `success` |
| `src` | Source address |

Older v6 may not support `with-extra-info`; parse the message text instead.

### 2.2 Successful login and logout

Successful logins and logouts use `system,info,account`:

```text
14:25:10 system,info,account user admin logged in from 203.0.113.45 via winbox
14:31:44 system,info,account user admin logged out from 203.0.113.45 via winbox
```

These are the entries that matter most: a failure is an attempt; a success is access.

### 2.3 Other relevant entries

- Configuration changes: `system,info item added by admin`, `firewall rule added by admin`, `user ... changed by ...`.
- Service changes: enabling/disabling services, changing ports, adding users.
- System events: reboot, clock change, package change.
- PPP/VPN: `ppp,info`, `l2tp,info`, `ovpn,info`, `wireguard` (limited logging).
- Hotspot: `hotspot,info,debug` for login events (if debug is enabled).

---

## 3. Log collection limits

RouterOS default logging:

- Four rules: `info`, `error`, `warning` to memory; `critical` to console.
- The memory buffer keeps about **1000 entries** by default and is lost on reboot.
- Debug messages are not logged unless a rule selects them.
- Remote syslog is optional and must be configured.
- The log buffer may contain only minutes or hours of data on a busy router.

Consequences:

- Absence of failed-login entries does **not** prove there were no attempts.
- A brute-force campaign may have rotated out of the buffer.
- The first question in any investigation is: "Where are the logs, and how far back do they go?"

```ros
/system/logging/print
/system/logging/action/print
/log/print
```

Look for a `remote` action with a real server address and rules that send `info`, `warning`, `error`, and `critical`. If remote logging is absent, state the visibility gap.

---

## 4. Detection queries

### 4.1 All failed logins in the buffer

```ros
/log/print where message~"login failure"
```

### 4.2 Failures for a specific service

```ros
/log/print where message~"login failure" and message~"via ssh"
/log/print where message~"login failure" and message~"via winbox"
/log/print where message~"login failure" and message~"via api"
```

### 4.3 Failures in a time window

```ros
/log/print where time>"2026-11-11 00:00:00" and time<"2026-11-11 06:00:00" and message~"login failure"
```

Note: if the entry is from today, RouterOS may print only the time. Supply the date carefully when correlating offline.

### 4.4 Successes and logouts

```ros
/log/print where topics~"account"
/log/print where message~"logged in"
/log/print where message~"logged out"
```

### 4.5 Configuration changes by a user

```ros
/log/print where topics~"system" and message~" by "
```

This is how you find "who changed the firewall" or "who added a user".

### 4.6 Defensive rules already present

```ros
/ip/firewall/address-list/print where list~"bruteforce|blacklist|connection"
/ip/firewall/filter/print stats where comment~"brute"
```

If the router already has MikroTik's staged SSH brute-force rules, the presence of entries in `connection1`/`connection2`/`connection3`/`bruteforce_blacklist` is evidence that connections were counted. It is not proof that passwords were guessed successfully.

---

## 5. Building counts without a SIEM

RouterOS CLI does not provide `group by`. To count failures per source:

1. Export the filtered log to a file **outside the router** (do not use `/log print file=` on the router).
2. Parse offline with a script or spreadsheet.
3. Count by `src` (v7 extra-info) or by the address after `from`.
4. Count distinct usernames and services per source.
5. Order by time and compute inter-arrival intervals.

Illustrative offline logic (not a RouterOS command):

```text
for each line matching "login failure":
    parse timestamp, user, source, service
    key = source
    increment failures[key]
    add user to users[key]
    add service to services[key]
    record first_seen, last_seen
sort by failures descending
```

Example synthetic result:

| Source | Failures | Users | Services | Window | First | Last |
|---|---:|---:|---|---|---|---|
| 203.0.113.45 | 412 | 37 | ssh | 18 min | 02:11:04 | 02:29:31 |
| 198.51.100.23 | 9 | 1 | winbox | 2 min | 09:14:02 | 09:16:10 |
| 192.0.2.77 | 2 | 2 | api | 1 min | 11:02:44 | 11:03:12 |

Interpretation:

- 412 failures across 37 users in 18 minutes from one source is a strong brute-force/spraying pattern.
- 9 failures for one user can be a typo or a stale saved password. It is not enough for a high-confidence attack finding unless the source is hostile or the pattern repeats.
- 2 failures across 2 users is weak evidence.

---

## 6. Heuristic thresholds (use with caution)

There is no universal RouterOS threshold. The following are **analysis heuristics**, not built-in values:

| Pattern | Heuristic | Confidence |
|---|---|---|
| Many failures, one source, short window | ≥10 failures in 5 min, or ≥50 in 1 h | MEDIUM to HIGH |
| Many usernames from one source | ≥5 distinct users in 10 min | HIGH for spraying |
| Multiple services from one source | ≥3 services in 1 h | HIGH for scanning/attack |
| Failure followed by success | Any success after ≥5 failures from same source within 30 min | HIGH for possible compromise |
| Low-and-slow | ≥3 failures/hour for ≥6 hours from one source | MEDIUM |
| Distributed | Same username, many sources, similar timing | MEDIUM (needs external correlation) |

Always report the actual counts and window, not just "high volume".

---

## 7. Correlation with connection data

Authentication logs tell you the outcome. Connection tracking tells you whether the service was reachable and what the TCP behavior looked like.

```ros
/ip/firewall/connection/print where dst-port=22
/ip/firewall/connection/print where dst-port=8291
/ip/firewall/connection/print where dst-port=8728
/ip/firewall/connection/print count-only
```

Look for:

- Many short-lived connections from one source to a management port.
- `syn-sent` or `syn-recv` states that never establish.
- A single established management session from an unexpected source.
- Connections to 22/8291/8728 from the WAN.

Caveats:

- A completed TCP login requires a routable source; source IP spoofing generally cannot complete a TCP handshake. This makes the source address relatively reliable for login attempts (unless a proxy or compromised host is used).
- NAT can make many internal clients appear as one public source.
- FastTrack and log rotation can hide attempts.

---

## 8. Classification matrix

| Evidence | Classification | Confidence |
|---|---|---|
| Failed logins only, one source, high rate | ATTEMPTED ATTACK | MEDIUM/HIGH |
| Failed logins only, low rate, one user | SUSPICIOUS ACTIVITY | LOW |
| Failures followed by a successful login from the same source | UNAUTHORIZED ACCESS (possible) | HIGH if timing and account match |
| Successful login from a known-good source, normal time | NORMAL (verify) | MEDIUM |
| New admin user + login from new source + config changes | CONFIRMED COMPROMISE (if all verified) | HIGH |
| No logs available | INSUFFICIENT EVIDENCE | — |

Do not label "unauthorized access" unless you can show the access was not legitimate. A successful login from an unknown IP is suspicious; it becomes unauthorized when the account owner or policy confirms it was not authorized.

---

## 9. False positives

- Administrator mistyping a password.
- A monitoring/backup tool with an old password.
- A NAT gateway representing many users as one source.
- Vulnerability scanners authorized by the owner.
- Load balancers or health checks that open and close connections.
- Shared accounts used by multiple people.
- Log entries duplicated across memory and disk actions.

Check the account, source, service, and time against known operations before escalating.

---

## 10. Recommendations

Priority order:

1. **Remove exposure** — close SSH/WinBox/API/WebFig on WAN; use WireGuard or another VPN.
2. **Strong authentication** — unique long passwords; SSH keys; disable password auth where possible (`/ip/ssh/set password-authentication=no` after keys are enrolled).
3. **Restrict sources** — firewall rules and `available-from`.
4. **Rate-limit** — MikroTik's staged address-list rules or equivalent; exempt trusted management addresses.
5. **Log centrally** — remote syslog/SIEM with enough retention; keep the clock synchronized.
6. **Alert on success after failure** — the highest-value detection.
7. **Review accounts** — remove unused users, avoid shared `admin`, use least privilege.
8. **Protect the VPN** — MFA at the VPN layer where possible.

Never apply these in read-only mode. Provide them as recommendations with a change plan.

---

## 11. Detection limitations

- Logs are volatile and small by default.
- Failed logins may not be logged if logging rules are missing or the service logs at debug level.
- Source addresses can be obscured by NAT or a proxy.
- Distributed attacks stay below per-source thresholds.
- A successful login may look identical to a legitimate one.
- RouterOS does not provide built-in geolocation, threat intelligence, or impossible-travel analysis.
- Log timestamps may lack a year for current-day entries and may be in a different time zone than the analyst.

---

## 12. Sources

- Log: <https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log>
- SSH brute-force protection (official): <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/user-guides/bruteforce-prevention>
- Securing your router: <https://manual.mikrotik.com/docs/getting-started/securing-your-router>
- SSH: <https://manual.mikrotik.com/docs/management-tools/ssh>
- User policies: <https://manual.mikrotik.com/docs/authentication-authorization-accounting/user>
- Connection tracking: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/connection-tracking>
- MITRE ATT&CK T1110: <https://attack.mitre.org/techniques/T1110/>
- MITRE ATT&CK T1078: <https://attack.mitre.org/techniques/T1078/>
- MITRE ATT&CK T1133: <https://attack.mitre.org/techniques/T1133/>
