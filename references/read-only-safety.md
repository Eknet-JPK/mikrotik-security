# Read-Only Safety Contract

**Scope:** How this skill interacts with a real MikroTik RouterOS device without changing it.
**Last reviewed:** 2026-11-11
**Applies to:** RouterOS v6 and v7, CLI, API, REST API, SSH, WinBox, and integration layers.

---

## 1. Why this file exists

Security analysis is not worth causing an outage, deleting evidence, or breaking a production router. The default operating mode of this skill is **STRICT READ-ONLY**. This file defines the exact boundary, how to enforce it technically where possible, and where the boundary is only behavioral.

There are three different things people call "read-only":

1. **Account-level read-only** — a RouterOS user whose group lacks write/reboot/policy/test/sensitive policies.
2. **Transport-level read-only** — an API proxy or middleware that only forwards allowlisted read commands.
3. **Application-level read-only** — this skill's own rule that it will only issue allowlisted read operations.

Only (1) and (2) are technical boundaries. (3) is a behavioral safeguard. Never tell a user they are "technically protected" because this skill says it is read-only.

> A RouterOS account with the `full` group can reboot, erase configuration, add users, and run scripts. If such credentials are used, the only thing preventing damage is the discipline of the code issuing commands. State this residual risk explicitly in the report.

---

## 2. Permitted operations

Only operations that read existing state are permitted. The canonical allowlist is below.

### 2.1 System and identity

```ros
/system/resource/print
/system/identity/print
/system/routerboard/print
/system/package/print
/system/clock/print
/system/ntp/client/print
/system/license/print
/system/health/print
/system/note/print
/system/device-mode/print
/system/history/print
/system/script/print
/system/scheduler/print
/system/watchdog/print
/system/logging/print
/system/logging/action/print
/log/print
```

`/system/history/print` is v7-only. `/system/health/print` is unavailable on some hardware. `/system/license/print` is not meaningful on every platform.

### 2.2 Network services and management plane

```ros
/ip/service/print
/ip/ssh/print
/snmp/print
/snmp/community/print
/ip/cloud/print
/ip/dns/print
/ip/dns/static/print
/ip/dns/cache/print
/ip/dhcp-server/print
/ip/dhcp-server/network/print
/ip/dhcp-server/lease/print
/ip/dhcp-client/print
/ip/pool/print
/ip/arp/print
/ip/neighbor/print
/ip/settings/print
```

`/ip/dns/cache/print` can be large. Use a filter or `.proplist` and a limit.

### 2.3 Firewall, NAT, and connection tracking

```ros
/ip/firewall/filter/print
/ip/firewall/filter/print stats
/ip/firewall/raw/print
/ip/firewall/raw/print stats
/ip/firewall/nat/print
/ip/firewall/mangle/print
/ip/firewall/address-list/print
/ip/firewall/connection/print
/ip/firewall/connection/tracking/print
/ipv6/firewall/filter/print
/ipv6/firewall/raw/print
/ipv6/firewall/address-list/print
/ipv6/firewall/connection/print
```

### 2.4 Interfaces, bridging, and routing

```ros
/interface/print
/interface/ethernet/print
/interface/bridge/print
/interface/bridge/port/print
/interface/bridge/vlan/print
/interface/vlan/print
/interface/list/print
/interface/list/member/print
/interface/wireless/print
/interface/wifi/print
/interface/wireguard/print
/ip/address/print
/ip/route/print
/ipv6/address/print
/ipv6/route/print
```

`/interface/wifi/print` exists only with the Wi-Fi 6/7 packages; legacy hardware uses `/interface/wireless/print`.

### 2.5 Users, VPN, and certificates

```ros
/user/print
/user/group/print
/user/active/print
/user/ssh-keys/print
/radius/print
/ppp/secret/print
/ppp/profile/print
/interface/wireguard/peers/print
/ip/ipsec/peer/print
/ip/ipsec/policy/print
/ip/ipsec/identity/print
/certificate/print
```

Use `.proplist` to avoid pulling sensitive fields. Never print private keys, passwords, secrets, or pre-shared keys.

### 2.6 Telemetry (bounded)

```ros
/interface/print stats
/interface/monitor-traffic interface=ether1 once
/ip/firewall/connection/print count-only
```

`monitor-traffic` without `once` streams continuously. In read-only mode, always use `once`, a short timeout, and a single interface. Do not run it on every interface at once.

---

## 3. Prohibited operations

The following are never permitted, even if the user says "it is just a small change" or "it will help the investigation".

### 3.1 State-changing configuration

- `add`, `set`, `remove`, `move`, `enable`, `disable`, `reset`, `clear`
- Creating, changing, or deleting: firewall rules, NAT, RAW, mangle, address lists, routes, addresses, bridges, VLANs, DHCP, DNS, queues, users, groups, certificates, VPN peers, scripts, schedulers, logging rules, services
- Changing passwords or expiring passwords
- Enabling/disabling interfaces or services
- Changing device-mode, LCD, LEDs, or hardware settings

### 3.2 Destructive or evidence-destroying operations

- `/system/reboot`, `/system/shutdown`, `/system/reset-configuration`
- `/system/backup/save`, `/system/backup/load`
- `/export`, `/export show-sensitive`
- `/system/package/update`, `/system/routerboard/upgrade`, `check-for-updates`
- `/file` creation, upload, download, deletion, or content modification
- `/log/print file=...` (this writes a file on the router)
- `/system/logging/action/clear`
- Clearing firewall or interface counters
- Removing connections from the conntrack table
- Killing active sessions or disconnecting clients

### 3.3 Active testing or traffic generation

- `ping`, `traceroute`, `flood-ping`, `bandwidth-test`, `speed-test`
- `torch`, `sniffer`, `packet capture`, `traffic-generator`
- Port knocking, vulnerability scanning, password spraying, exploitation
- Any command that sends packets to a third party

### 3.4 Execution

- `/system/script/run`, `/import`, `/system/scheduler` execution
- `/tool fetch` (downloads or uploads data)
- Containers, `/container/shell`, or any shell-like execution
- Constructing a command from log text, user text, or API data without strict validation

> If a command is not on the permitted list, the correct action is to **stop**, explain why, and ask for a safe alternative. Do not "try it and see".

---

## 4. Recommended technical enforcement

The skill cannot create accounts or change the router. The following are recommendations for the router owner to apply **outside** this skill, with a change window and rollback plan.

### 4.1 Dedicated read-only RouterOS account

RouterOS built-in groups are not truly read-only. The official documentation notes that the built-in `read` group still includes `reboot` and `sensitive`. Create a custom group with only the policies required for the transport:

```ros
/user/group/add name=security-audit \
    policy=read,api,rest-api,ssh,winbox,web

/user/add name=sec-auditor group=security-audit \
    password="<strong-unique-password>" \
    address=192.0.2.0/24
```

What this does:

- `read` — read configuration and state.
- `api` / `rest-api` — allow API and REST access.
- `ssh` / `winbox` / `web` — allow the chosen management transports. Remove any transport you do not use.
- No `write` — configuration changes fail.
- No `policy` — cannot change users or permissions.
- No `reboot` — cannot reboot.
- No `test` — cannot run ping, traceroute, torch, or bandwidth tests.
- No `sensitive` — cannot see passwords, keys, or other secrets.
- No `ftp`, `romon`, `sniff`, `local` — reduces the attack surface of the audit account.

Expected verification after the administrator applies it:

```text
[admin@MikroTik] > /user/group/print where name=security-audit
Flags: * - default
 0   name="security-audit"
     policy=read,ssh,winbox,web,api,rest-api,!local,!telnet,!ftp,!reboot,
            !write,!policy,!test,!sniff,!sensitive,!romon
```

Interpretation: the exclamation marks are explicit revocations. If `write`, `policy`, `reboot`, `test`, or `sensitive` appears without `!`, the group is not read-only enough for an untrusted auditor.

**Limitations**

- `read` still exposes the full configuration, including internal topology and addresses.
- Some RouterOS versions may not support every policy name. If the command fails, use the version-appropriate subset and document it.
- A read-only account can still consume CPU with heavy `print` calls. Rate-limit and paginate.
- Account creation itself is a change. This skill must not perform it.

### 4.2 Read-only API proxy

For repeatable or multi-router audits, place a proxy between the skill and RouterOS that:

1. Accepts only `POST /rpc` with a JSON body containing `menu` and `command`.
2. Allows only command words matching:
   `^/(system|log|ip|ipv6|interface|user|snmp|certificate|ppp|radius|tool)[a-z0-9/_-]*/(print|getall|getone)$`
3. Rejects any attribute name in `{file, file-name, save, export, backup, script, run, execute}`.
4. Rejects command words containing `add`, `set`, `remove`, `enable`, `disable`, `reboot`, `reset`, `clear`, `update`, `upgrade`, `fetch`, `ping`, `traceroute`, `torch`, `sniffer`.
5. Enforces a maximum response size, a per-call timeout, and a concurrency limit.
6. Logs every call (menu, command, filters, row count, duration) without logging credentials.
7. Uses a dedicated read-only RouterOS account.

A proxy is the only way to make the allowlist a technical boundary rather than a suggestion.

### 4.3 REST API

If REST is used:

- Allow only `GET`.
- Allow only paths under `/rest/` that map to the menus in section 2.
- Reject `POST`, `PUT`, `PATCH`, `DELETE`.
- Reject query parameters named `file`, `save`, `export`, or `backup`.
- Require HTTPS (`www-ssl`) with a valid certificate; do not disable certificate verification.
- Use Basic Auth over TLS only, never over plain HTTP.

REST API is a RouterOS v7 feature. Do not attempt it on v6.

---

## 5. API allowlist (implementation guidance)

The RouterOS API is command-oriented. The safety property is simple: **the command word must end in a read verb, and the path must be on the menu allowlist**.

### 5.1 Command word validation

Illustrative pseudo-code — not a RouterOS command:

```text
ALLOWED_VERBS = {"print", "getall", "getone"}
ALLOWED_ROOTS = {"system", "log", "ip", "ipv6", "interface", "user",
                 "snmp", "certificate", "ppp", "radius", "tool"}

function validate(command):
    if not command.startsWith("/"): reject
    if command.contains("..") or command.contains("//"): reject
    parts = command.trim("/").split("/")
    if parts.length < 3: reject
    if parts[0] not in ALLOWED_ROOTS: reject
    verb = parts[-1]
    if verb not in ALLOWED_VERBS: reject
    if any(part in FORBIDDEN for part in parts): reject
    return normalized_path(parts[0..-2]) + "/" + verb
```

`FORBIDDEN` must include at least: `add`, `set`, `remove`, `move`, `enable`, `disable`, `reset`, `clear`, `reboot`, `shutdown`, `export`, `import`, `backup`, `restore`, `update`, `upgrade`, `downgrade`, `fetch`, `run`, `execute`, `script`, `scheduler`, `file`, `sniffer`, `torch`, `ping`, `traceroute`, `bandwidth-test`, `traffic-generator`, `password`, `expire-password`, `kick`.

Do not rely on a blocklist alone. Use an allowlist of exact menu paths where possible, and validate the final normalized path again after decoding.

### 5.2 Attribute and query validation

For read commands:

- Allow filter attributes (`=chain=input`, `=dst-port=22`, `=topics~...`) because they only narrow a read.
- Allow `.proplist=...` to reduce data exposure and response size.
- Allow `=count-only=` only as an explicit boolean.
- **Reject** attribute names `file`, `file-name`, `save`, `export`, `backup`, `script`, `run`, `execute`, `interval`, `duration` (except a bounded timeout implemented client-side).
- Reject values containing newlines, NUL bytes, or RouterOS command separators.
- Cap the number of query words and the total sentence length.

### 5.3 Response handling

- Cap rows (for example 500 per call) and page with queries. Do not pull the full conntrack table.
- Use `.proplist` to exclude secrets: never request `password`, `private-key`, `pre-shared-key`, `secret`, `passphrase`, `key`.
- Treat `!trap` as a failed read, not as permission to retry with a different command.
- If the router returns an unexpected field, do not echo it into the report.

### 5.4 What never to send

The official API documentation itself uses these as command examples; they are **examples of what this skill must never send**:

```text
/system/reboot
/user/active/listen
/interface/vlan/remove
```

`listen` is technically read-only but long-running and can disclose session data. In strict mode, do not use it. Prefer a bounded `print` snapshot.

---

## 6. Credential handling

- Never ask for a password in chat.
- Never place credentials in a command line, environment dump, log, report, commit, or screenshot.
- Prefer an existing authenticated client, a read-only account configured out-of-band, or an approved secret manager.
- If an integration decrypts credentials in memory, never print the plaintext or the decryption key.
- Redact source addresses only when necessary for privacy; preserve them internally for correlation.
- If a credential is accidentally exposed, instruct the owner to rotate it and review authentication logs immediately.
- Do not write `.env`, `*.key`, `*.pem`, `id_rsa`, or credential files into the repository.

---

## 7. Evidence preservation

If compromise is suspected:

1. Do **not** reboot, reset, upgrade, clear logs, or remove connections.
2. Record the current time, router clock, uptime, and version.
3. Capture read-only snapshots: logs, users, active sessions, scripts, schedulers, services, firewall, routes, DNS, certificates, `/system/history` (v7), `/system/device-mode/print`.
4. Record counts, not just examples. State the sampling window.
5. Preserve external evidence: syslog/SIEM exports, NetFlow, upstream firewall logs, switch logs, EDR alerts.
6. Advise isolation through an out-of-band, authorized administrative action. This skill must not perform the isolation itself.
7. Document the chain of custody and any gaps.

---

## 8. Detection limitations of the read-only posture

Read-only access is safe, but it limits what can be concluded:

- **No packet capture** — payload-based detection (malware, C2 content, DNS tunneling content) is out of scope.
- **No active probing** — you cannot confirm whether a service is reachable from the internet by scanning it.
- **No remediation** — you can recommend, not apply.
- **Snapshot bias** — conntrack and counters show the present, not the past.
- **Log gaps** — default memory logs are small and volatile.
- **FastTrack** — established/related traffic may bypass filter rules and some counters.
- **NAT** — internal sources may be hidden behind a public address.
- **Encryption** — TLS, SSH, VPN, and DoH hide content.

State these limits rather than filling gaps with assumptions.

---

## 9. Pre-flight checklist

Before the first read:

- [ ] Target and scope confirmed.
- [ ] Data source and time window confirmed.
- [ ] RouterOS major version known or about to be read.
- [ ] Account type known (dedicated read-only vs full).
- [ ] Transport is encrypted (SSH, API-SSL, HTTPS) or local.
- [ ] No credentials in the prompt, logs, or files.
- [ ] Read plan uses bounded queries and `.proplist`.
- [ ] No command from the prohibited list is queued.
- [ ] Report will state the enforcement method and residual risk.

---

## 10. Sources

- MikroTik RouterOS manual, "Securing your router": <https://manual.mikrotik.com/docs/getting-started/securing-your-router>
- MikroTik RouterOS manual, "User" (policies, read-only user): <https://manual.mikrotik.com/docs/authentication-authorization-accounting/user>
- MikroTik RouterOS manual, "Services": <https://manual.mikrotik.com/docs/system-information-and-utilities/services>
- MikroTik RouterOS manual, "API": <https://manual.mikrotik.com/docs/developer-guides/api>
- MikroTik RouterOS manual, "Log": <https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log>
- MikroTik RouterOS manual, "Connection tracking": <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/connection-tracking>
- MikroTik security announcements: <https://mikrotik.com/supportsec>
- NIST CSF 2.0, Protect and Detect functions: <https://www.nist.gov/cyberframework>
