# Security Incident Investigation

**Scope:** A structured, evidence-based workflow for investigating suspected RouterOS compromise or attack.
**Last reviewed:** 2026-11-11
**Applies to:** RouterOS v6 and v7; adapt commands to the version.

---

## 1. Principles

1. **Evidence before action.** Do not reboot, reset, upgrade, or clear logs while evidence is volatile.
2. **Read-only by default.** This skill observes; the owner remediates.
3. **Separate fact from inference.** State what you saw, what it means, and how confident you are.
4. **Corroborate.** One log line is not a compromise. Multiple independent indicators are.
5. **Preserve the timeline.** Record time zone, clock accuracy, uptime, and data source.
6. **Protect privacy.** Redact credentials and unnecessary personal data; keep source addresses for correlation.
7. **Document gaps.** Missing logs are a finding, not a reason to guess.

---

## 2. The ten-step workflow

### Step 1 — Identify the incident

Clarify:

- What was reported? (slow network, unauthorized login, changed config, malware alert, ISP notice, user complaint)
- When did it start? (local time and time zone)
- Which router(s) and which network segments?
- Who is the owner/authority? Who can authorize access?
- Is there a suspected data breach or only availability impact?
- Are there legal/regulatory obligations?

Create an incident ID and a working timeline. Do not contact the suspected attacker.

### Step 2 — Collect evidence

Collect before changing anything. Use read-only commands and bounded queries.

Minimum set:

```ros
/system/resource/print
/system/identity/print
/system/routerboard/print
/system/package/print
/system/clock/print
/system/ntp/client/print
/system/device-mode/print
/system/history/print
/system/script/print
/system/scheduler/print
/system/logging/print
/system/logging/action/print
/log/print
/ip/service/print
/ip/ssh/print
/user/print
/user/group/print
/user/active/print
/user/ssh-keys/print
/ip/firewall/filter/print
/ip/firewall/filter/print stats
/ip/firewall/raw/print
/ip/firewall/nat/print
/ip/firewall/address-list/print
/ip/firewall/connection/print count-only
/ip/firewall/connection/tracking/print
/ip/route/print
/ip/dns/print
/ip/dns/static/print
/ip/arp/print
/ip/dhcp-server/lease/print
/interface/print stats
```

Also collect:

- external syslog/SIEM exports;
- NetFlow/sFlow records;
- upstream firewall/ISP logs;
- switch logs (MAC table, DHCP snooping, DAI);
- EDR/AV alerts;
- user reports and change tickets.

Record:

- collection time and collector;
- router uptime and clock;
- command used and row count;
- any errors or timeouts;
- hash or checksum of exported evidence where practical.

Do not use `/export` (it can expose secrets and is prohibited), `/log print file=` (writes to router), or `/system/backup/save`.

### Step 3 — Analyze logs

Use `references/security-log-analysis.md`.

Questions:

- Who logged in, from where, via which service, and when?
- Were there failures before a success?
- What configuration changed, and by which user?
- Were users, scripts, schedulers, firewall rules, NAT, DNS, or services changed?
- Did the router reboot? When? Why?
- Are there gaps? Why?
- Is logging still configured correctly?

Key queries:

```ros
/log/print where topics~"account"
/log/print where message~"login failure"
/log/print where topics~"system" and message~" by "
/log/print where topics~"critical"
/system/history/print
```

### Step 4 — Analyze network connections

Use `references/network-traffic-analysis.md`.

Questions:

- Are there active management sessions from unexpected sources?
- Are there outbound connections to unknown destinations?
- Is there a scan, flood, or beaconing pattern?
- Is conntrack near capacity?
- Are NAT/dst-nat rules exposing something new?
- Is the DNS resolver open or redirected?

Commands:

```ros
/ip/firewall/connection/tracking/print
/ip/firewall/connection/print count-only
/ip/firewall/connection/print where dst-port=22
/ip/firewall/connection/print where src-address=203.0.113.45
/user/active/print
```

Expected shape (synthetic):

```text
[admin@edge-rtr] > /ip/firewall/connection/tracking/print
        enabled: auto
      max-entries: 1048576
    total-entries: 18422

[admin@edge-rtr] > /user/active/print
Columns: NAME, ADDRESS, WHEN, VIA
#   NAME   ADDRESS        WHEN      VIA
0   admin  192.0.2.10     14:02:11  winbox
1   admin  203.0.113.45   02:31:19  ssh
```

Interpretation: two concurrent `admin` sessions from different networks are a reason to confirm identity, not proof of compromise. A session that has been active since the suspicious login time is a strong pivot.

### Step 5 — Identify source and destination

For each indicator, record:

- source IP and port;
- destination IP and port;
- protocol;
- first/last seen;
- service/username;
- whether NAT was applied;
- whether the source is internal, external, or the router itself;
- ownership/geo/threat-intel if available (label as external context, not fact from RouterOS).

Do not attribute an attack to a country or organization based only on an IP address. NAT, proxies, and compromised hosts distort attribution.

### Step 6 — Build the timeline

Use a single time zone. Include:

- first suspicious event;
- escalation (more sources, more targets, higher rate);
- successful access (if any);
- configuration changes;
- new files/scripts/schedulers;
- outbound connections;
- detection/response actions;
- reboots and log gaps.

Synthetic example:

```text
2026-11-11 02:11:04  First SSH login failure from 203.0.113.45
2026-11-11 02:11–02:29  412 failures across 37 usernames (SSH)
2026-11-11 02:31:19  Successful SSH login as admin from 203.0.113.45
2026-11-11 02:33:02  User svc-backup added by admin
2026-11-11 02:34:10  Firewall rule added by admin (input accept tcp/8443)
2026-11-11 02:35:44  Script "sync" added by admin
2026-11-11 02:40:12  Outbound TCP 198.51.100.99:443 from router
2026-11-11 03:02:00  No further account events; session still active
```

A timeline with gaps is still useful; mark the gaps.

### Step 7 — Determine the attack pattern

Map observed behavior to a pattern, with ATT&CK references:

| Pattern | Evidence | ATT&CK |
|---|---|---|
| Password guessing | Failure bursts, many usernames | T1110 |
| Valid account abuse | Success after failures, unusual source | T1078 |
| External remote service | Exposed SSH/WinBox/API/WebFig | T1133 |
| Reconnaissance | Many ports/hosts, scan logs | T1046, T1595 |
| Flood | pps/bps spike, conntrack pressure | T1498, T1499 |
| Persistence | New user, script, scheduler, firewall rule | T1136, T1053, T1543 |
| Traffic manipulation | Route/DNS/firewall change | T1556, T1565 |
| C2 | Periodic outbound connections | T1071, T1571 |
| Exfiltration | Asymmetric outbound volume | T1041 |
| Credential access | Config/credential file read | T1552 |

Do not force a pattern. If the evidence fits multiple patterns, say so.

### Step 8 — Assess impact

Consider:

- **Confidentiality** — credentials, config, traffic, user data.
- **Integrity** — routes, DNS, NAT, firewall, firmware, scripts.
- **Availability** — outage, reboot, flood, link saturation.
- **Scope** — router only, one segment, or all traffic behind it.
- **Duration** — how long the access/flood lasted.
- **Persistence** — will it survive reboot?
- **Downstream** — other routers, RADIUS, hotspot, VPN peers, managed switches.

A router compromise is rarely limited to the router: it can intercept or redirect all traffic that traverses it.

### Step 9 — Determine confidence

Use the definitions in `SKILL.md`:

- HIGH — multiple independent, time-correlated sources; mechanism verified.
- MEDIUM — one strong source plus context; alternatives remain.
- LOW — weak/incomplete/ambiguous.

Also state the **status**:

- ATTEMPTED ATTACK
- SUSPICIOUS ACTIVITY
- UNAUTHORIZED ACCESS
- CONFIRMED COMPROMISE
- INSUFFICIENT EVIDENCE

Examples:

- 400 failed logins, no success → ATTEMPTED ATTACK (HIGH for the attempts, no compromise).
- Failed logins then success from same source, but the admin confirms it was them → NORMAL/benign (document).
- Failed logins then success, admin denies it, plus new user/script → CONFIRMED COMPROMISE (HIGH) if all verified.
- New admin user but no login evidence and no change ticket → SUSPICIOUS ACTIVITY / UNAUTHORIZED ACCESS depending on verification.
- Router rebooted, logs lost, no other evidence → INSUFFICIENT EVIDENCE.

### Step 10 — Recommendations

Provide:

1. **Immediate containment** (owner action): isolate the management plane, block the source at the upstream firewall, disable compromised accounts, preserve evidence.
2. **Eradication**: remove unauthorized users/scripts/schedulers/rules, patch the entry vector, rotate credentials and keys.
3. **Recovery**: restore from a known-good configuration, verify integrity, monitor.
4. **Prevention**: close exposure, enforce least privilege, patch, segment, log centrally, alert.
5. **Verification**: how to confirm the fix (without penetration testing).

Do not perform containment or remediation yourself.

---

## 3. Evidence preservation and chain of custody

- Record who collected what, when, and how.
- Keep raw outputs unmodified; store analysis separately.
- Use checksums for exported files.
- Do not edit logs or screenshots.
- Store evidence with access control.
- Retain according to policy/legal requirements.
- If law enforcement or legal action is possible, consult the owner's legal team before deleting anything.

---

## 4. Containment guidance (for the owner)

Order of operations matters:

1. **Preserve** volatile evidence (logs, conntrack, active sessions, memory-only data).
2. **Isolate** the management plane: restrict management to a trusted network, preferably out-of-band.
3. **Block** confirmed malicious sources at the upstream firewall/ISP, not only on the router.
4. **Disable** compromised accounts and revoke keys.
5. **Do not reboot** until evidence is preserved, unless availability requires it.
6. **Patch** the entry vector before restoring service.
7. **Monitor** for recurrence.

A reboot destroys memory logs and conntrack. A configuration reset destroys evidence and may remove the attacker's persistence but also your ability to understand the incident.

---

## 5. Special cases

### 5.1 Suspected router compromise

Look for:

- unknown users/groups;
- new SSH keys;
- new scripts/schedulers;
- firewall/NAT/DNS changes;
- unexpected routes;
- new certificates;
- enabled services (API, Telnet, FTP, MAC server, SNMP);
- outbound connections;
- `/system/device-mode/print` flagged status;
- a `critical` log entry about a flagged device.

If the 2026 SSH/WebFig issues are in scope, check the version and fixed releases in `references/vulnerability-assessment.md`.

### 5.2 Suspected credential compromise

- Review successful logins, not just failures.
- Check source addresses and service.
- Check for new users/keys and permission changes.
- Rotate credentials only after preserving evidence.
- Consider that the same password may be reused on other devices.

### 5.3 Suspected DDoS

- Distinguish router-target vs host-target vs uplink saturation.
- Preserve logs before rebooting.
- Engage the ISP early.
- Do not block individual sources as the only response.
- See `references/ddos-detection.md`.

### 5.4 Suspected insider/LAN attack

- Internal scans, ARP spoofing, rogue DHCP, lateral movement.
- RouterOS alone may be insufficient; use switch/IDS/EDR data.
- Preserve switch MAC tables and DHCP snooping logs.
- Do not accuse an individual based on an IP/MAC alone; DHCP and NAT can misattribute.

---

## 6. Communication

- Give the owner facts, uncertainty, and recommended actions.
- Avoid speculation about attribution.
- Separate technical findings from business impact.
- Provide a short executive summary and a detailed technical annex.
- State what you did **not** verify.
- Do not publish router details, credentials, or user data.

---

## 7. Post-incident review

- What was the entry vector?
- How long was the dwell time?
- What detection worked or failed?
- Were logs sufficient?
- Was the response timely?
- What controls would have prevented or detected it?
- Update the audit baseline and monitoring.

Map improvements to NIST CSF 2.0 functions: Govern, Identify, Protect, Detect, Respond, Recover.

---

## 8. Limitations

- RouterOS logs may be incomplete or volatile.
- Conntrack is a snapshot, not a historical flow record.
- No payload inspection.
- NAT and proxies obscure attribution.
- The skill cannot perform endpoint forensics, memory analysis, or malware analysis.
- The skill cannot legally authorize access or data collection.
- External threat intelligence may be wrong or stale.
- A clean configuration does not prove the router was never compromised; persistence may be subtle.

---

## 9. Sources

- Log: <https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log>
- Connection tracking: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/connection-tracking>
- User policies: <https://manual.mikrotik.com/docs/authentication-authorization-accounting/user>
- Securing your router: <https://manual.mikrotik.com/docs/getting-started/securing-your-router>
- MikroTik security announcements: <https://mikrotik.com/supportsec>
- MITRE ATT&CK: <https://attack.mitre.org/>
- NIST CSF 2.0: <https://www.nist.gov/cyberframework>
- CISA incident response: <https://www.cisa.gov/>
