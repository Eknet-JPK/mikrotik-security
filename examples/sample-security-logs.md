# Synthetic Security Log Sample

> **SYNTHETIC DATA — NOT FROM A REAL ROUTER.**
> All addresses use RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
> All MAC addresses use the RFC 7042 documentation range (00:00:5E:00:53:xx).
> Users, hostnames, and events are fictional. Do not treat this as threat intelligence.

**Purpose:** Practice reading RouterOS logs, building a timeline, and distinguishing an attempted attack from a confirmed compromise.

---

## 1. Scenario

Router: `edge-rtr`, RouterOS 7.16.2, management address 192.0.2.1, LAN 192.168.88.0/24, WAN `ether1`.
Log source: default memory buffer, no remote syslog.
Time zone: Asia/Bangkok (+07:00).
Reported symptom: "the internet was slow around 02:00 and someone may have logged in."

The following is a representative excerpt. The full synthetic dataset contains 412 failed SSH logins between 02:11:04 and 02:29:31 from 203.0.113.45.

---

## 2. Log excerpt

```text
2026-11-10 23:41:02 system,info,account user admin logged out from 192.0.2.10 via winbox
2026-11-10 23:41:05 system,info,account user admin logged in from 192.0.2.10 via winbox
2026-11-10 23:55:18 dhcp,info defconf assigned 192.168.88.37 for 00:00:5E:00:53:37
2026-11-11 00:02:44 interface,info ether1 link down
2026-11-11 00:02:51 interface,info ether1 link up (speed 1G, full duplex)
2026-11-11 00:15:09 firewall,info WAN-DROP input: in:ether1 out:(none), src-mac 00:00:5E:00:53:91,
    proto TCP, 198.51.100.77:44112->192.0.2.1:8291, len 60
2026-11-11 00:15:12 firewall,info WAN-DROP input: in:ether1 out:(none), src-mac 00:00:5E:00:53:91,
    proto TCP, 198.51.100.77:44118->192.0.2.1:22, len 60
2026-11-11 01:58:02 system,info,account user admin logged out from 192.0.2.10 via winbox
2026-11-11 02:03:11 dhcp,info defconf assigned 192.168.88.41 for 00:00:5E:00:53:41
2026-11-11 02:11:04 system,error,critical login failure for user admin from 203.0.113.45 via ssh
2026-11-11 02:11:06 system,error,critical login failure for user root from 203.0.113.45 via ssh
2026-11-11 02:11:09 system,error,critical login failure for user test from 203.0.113.45 via ssh
2026-11-11 02:11:12 system,error,critical login failure for user ubnt from 203.0.113.45 via ssh
2026-11-11 02:11:15 system,error,critical login failure for user support from 203.0.113.45 via ssh
2026-11-11 02:14:22 system,error,critical login failure for user admin from 203.0.113.45 via ssh
2026-11-11 02:18:40 system,error,critical login failure for user oracle from 203.0.113.45 via ssh
2026-11-11 02:22:11 system,error,critical login failure for user postgres from 203.0.113.45 via ssh
2026-11-11 02:26:03 system,error,critical login failure for user admin from 203.0.113.45 via ssh
2026-11-11 02:29:31 system,error,critical login failure for user admin from 203.0.113.45 via ssh
2026-11-11 02:31:19 system,info,account user admin logged in from 203.0.113.45 via ssh
2026-11-11 02:33:02 system,info user svc-backup added by admin
2026-11-11 02:33:44 system,info user group changed by admin
2026-11-11 02:34:10 system,info firewall rule added by admin
2026-11-11 02:34:12 system,info firewall rule moved by admin
2026-11-11 02:35:44 system,info script added by admin
2026-11-11 02:36:02 system,info scheduler added by admin
2026-11-11 02:40:12 firewall,info OUT-CONN forward: in:bridge out:ether1, src-mac 00:00:5E:00:53:01,
    proto TCP, 192.168.88.10:51044->198.51.100.99:443, len 60
2026-11-11 02:41:19 system,info,account user svc-backup logged in from 198.51.100.99 via api
2026-11-11 02:44:03 system,info,account user admin logged out from 203.0.113.45 via ssh
2026-11-11 02:51:17 dhcp,info defconf deassigned 192.168.88.41 for 00:00:5E:00:53:41
2026-11-11 03:02:00 system,info,account user svc-backup logged out from 198.51.100.99 via api
2026-11-11 03:14:55 firewall,info WAN-DROP input: in:ether1 out:(none), src-mac 00:00:5E:00:53:92,
    proto TCP, 198.51.100.88:51222->192.0.2.1:22, len 60
2026-11-11 04:00:01 system,info,account user admin logged in from 192.0.2.10 via winbox
2026-11-11 04:00:05 system,info,account user admin logged out from 192.0.2.10 via winbox
```

v7 `with-extra-info` would render the critical lines as:

```text
2026-11-11 02:11:04 system,error,critical login failure for user admin from 203.0.113.45 via ssh
    app=ssh duser=admin outcome=failure src=203.0.113.45
2026-11-11 02:31:19 system,info,account user admin logged in from 203.0.113.45 via ssh
    app=ssh duser=admin outcome=success src=203.0.113.45
```

---

## 3. Analysis tasks

Answer before reading section 4.

1. What is the brute-force window, source, and number of targeted usernames?
2. Was there a successful authentication? From where and to which account?
3. What changed immediately after the successful login?
4. What evidence suggests persistence or C2?
5. Classify the incident: attempted attack, suspicious activity, unauthorized access, confirmed compromise, or insufficient evidence. State confidence.
6. What evidence is missing or weak?
7. What would raise confidence to "confirmed compromise"?
8. What would lower confidence or explain the events benignly?

---

## 4. Worked analysis

### 4.1 Brute force

- Source: 203.0.113.45.
- Window: 02:11:04–02:29:31 (about 18 minutes).
- Failures: 412 (full synthetic dataset).
- Usernames: 37, including `admin`, `root`, `test`, `ubnt`, `support`, `oracle`, `postgres`.
- Service: SSH.
- Pattern: high-rate, multi-username guessing → consistent with brute force/password spraying.
- Classification: **ATTEMPTED ATTACK**, confidence **HIGH** for the attempts.

### 4.2 Successful login

- 02:31:19: `user admin logged in from 203.0.113.45 via ssh`.
- Same source as the failures, 1m48s after the last failure.
- This is a **failure→success** pattern: the strongest single indicator of possible credential compromise.
- Classification: **UNAUTHORIZED ACCESS (possible)**, confidence **HIGH** that the login occurred, **MEDIUM** that it was unauthorized until the owner confirms it was not them.

### 4.3 Post-login changes

- 02:33:02: user `svc-backup` added.
- 02:33:44: user group changed.
- 02:34:10–12: firewall rule added and moved.
- 02:35:44: script added.
- 02:36:02: scheduler added.

These are classic persistence actions. If the admin did not make them, they raise the incident to **CONFIRMED COMPROMISE** with **HIGH** confidence (subject to verifying the objects and the session).

### 4.4 Outbound and API activity

- 02:40:12: internal host 192.168.88.10 connects to 198.51.100.99:443.
- 02:41:19: `svc-backup` logs in via API from 198.51.100.99.
- 02:51:17: DHCP lease for 192.168.88.41 is deassigned.
- 03:02:00: `svc-backup` logs out.

Interpretation:

- The API login from an external address using a newly created account is highly suspicious.
- The outbound 443 connection could be C2 or a legitimate update; it needs threat intel/flow analysis.
- The DHCP deassignment is likely unrelated noise, but note it.

### 4.5 Log noise

- 00:15 and 03:14 WAN drops to 8291/22 from 198.51.100.77/88: background internet scanning, blocked by the firewall. Not a compromise.
- 00:02 ether1 flap: possible ISP/cable issue; not an attack by itself.
- 04:00 admin login from 192.0.2.10: likely the normal administrator. Verify with the owner.

### 4.6 Classification

**CONFIRMED COMPROMISE — HIGH confidence**, if and only if:

- the owner confirms the 02:31 login and subsequent changes were not authorized; and
- the new user/script/scheduler/firewall rule are verified to exist and are unexplained.

Without owner confirmation, the defensible classification is:

**UNAUTHORIZED ACCESS (possible) — MEDIUM confidence**, with a recommendation to treat it as a compromise until disproven.

### 4.7 Missing evidence

- No remote syslog; the memory buffer may have rotated.
- No command output for the new user, script, scheduler, or firewall rule.
- No `/system/history` output.
- No conntrack snapshot at the time.
- No NetFlow/IDS data for 198.51.100.99.
- No confirmation of whether 203.0.113.45 is a known admin/VPN address.
- The log excerpt may be incomplete.

### 4.8 What would raise confidence

- The new objects exist and reference external infrastructure.
- `/system/history` shows the changes were made during the 203.0.113.45 session.
- The admin denies the login and changes.
- The script/scheduler contacts 198.51.100.99 or downloads a payload.
- Threat intelligence links 203.0.113.45 or 198.51.100.99 to malicious activity.
- Other routers show the same pattern.

### 4.9 What would lower confidence

- The owner confirms they logged in from 203.0.113.45 (for example via a VPN) and made the changes.
- The source is a known authorized scanner or automation host.
- The "new user" is part of a documented change ticket.
- The timestamps are wrong due to clock drift, and the events do not correlate.

---

## 5. Recommended actions (for the fictional owner)

1. Preserve logs and capture the current objects before any reboot.
2. Confirm with the administrator whether the 02:31 login was legitimate.
3. If not legitimate: isolate the management plane, disable `svc-backup`, remove unauthorized script/scheduler/firewall rules, rotate all credentials and keys.
4. Review `/system/history`, `/user/active/print`, `/system/script/print`, `/system/scheduler/print`, `/ip/firewall/filter/print`, `/ip/firewall/nat/print`, `/ip/dns/static/print`.
5. Block 203.0.113.45 and 198.51.100.99 at the upstream firewall, not only on the router.
6. Add remote syslog/SIEM and alert on failure→success.
7. Patch to a current fixed RouterOS release after evidence is preserved.
8. Review whether SSH was exposed to WAN; if so, close it and use a VPN.

These are recommendations. This skill must not perform them.

---

## 6. Key lessons

- Background scans are normal; do not report every WAN drop as an attack.
- The failure→success sequence is the pivot point.
- Configuration changes after a suspicious login are the difference between "attempt" and "compromise".
- A new account plus an external API login is a persistence indicator.
- Logs alone may not prove authorization; owner confirmation matters.
- Missing logs are a finding, not a "no incident" conclusion.

---

## 7. Sources for the log semantics

- Log: <https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log>
- SSH brute-force protection: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/user-guides/bruteforce-prevention>
- User policies: <https://manual.mikrotik.com/docs/authentication-authorization-accounting/user>
- MITRE ATT&CK T1110, T1078, T1133: <https://attack.mitre.org/>
