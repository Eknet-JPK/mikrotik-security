# Synthetic MikroTik Security Audit Report

> **SYNTHETIC REPORT — FOR TRAINING ONLY.**
> Router, addresses, users, and findings are fictional. Addresses use RFC 5737 documentation ranges.
> Do not reuse this report as evidence about a real device.

---

## MikroTik Security Audit Report

### Router Information

| Field | Value |
|---|---|
| Router identity | `edge-rtr` |
| Management IP | 192.0.2.1 |
| RouterOS version | 7.16.2 (stable), build 2026-02-10 |
| Architecture | arm64 |
| Board / serial | RB5009UG+S+ / HEQ08SYNTHETIC |
| RouterBOOT firmware | current 7.13, upgrade 7.13 |
| Audit date and time | 2026-11-11 14:00–15:10 +07:00 |
| Data source | Live read-only API-SSL, plus supplied configuration notes |
| Connection status | Reachable; API-SSL; certificate valid |
| Read-only enforcement | Dedicated `security-audit` account (no write/policy/reboot/test/sensitive), application allowlist |
| Auditor | Synthetic example |
| Scope | Router configuration, logs, users, services, firewall, DNS, exposure |
| Exclusions | Endpoint forensics, ISP flow data, switch logs, penetration testing |

### Security Status

**SUSPICIOUS**

Reason: the router has material exposure and an unresolved authentication event. There is no verified evidence of a successful compromise, and the owner has not confirmed whether the successful login was legitimate.

---

## Summary of Findings

| ID | Category | Severity | Confidence | Status | Title |
|---|---|---|---|---|---|
| F-01 | Exposure / Authentication | HIGH | MEDIUM | ATTEMPTED ATTACK | SSH reachable from WAN; brute force and an unconfirmed successful login |
| F-02 | Vulnerability | HIGH | HIGH | SUSPICIOUS ACTIVITY | RouterOS 7.16.2 is affected by fixed, critical 2026 issues |
| F-03 | Firewall | HIGH | HIGH | SUSPICIOUS ACTIVITY | No IPv6 firewall; IPv6 enabled |
| F-04 | DNS | HIGH | HIGH | SUSPICIOUS ACTIVITY | DNS resolver open to WAN |
| F-05 | Firewall / NAT | HIGH | HIGH | SUSPICIOUS ACTIVITY | Unrestricted RDP port forward to a workstation |
| F-06 | Services | MEDIUM | HIGH | SUSPICIOUS ACTIVITY | UPnP and SOCKS enabled |
| F-07 | Users | MEDIUM | HIGH | SUSPICIOUS ACTIVITY | Shared `admin` account; no source restriction |
| F-08 | Logs | MEDIUM | HIGH | SUSPICIOUS ACTIVITY | No remote syslog; ~1000-entry volatile buffer |
| F-09 | Firewall | MEDIUM | HIGH | SUSPICIOUS ACTIVITY | FastTrack placed before the blocklist rule |
| F-10 | System | LOW | HIGH | SUSPICIOUS ACTIVITY | RouterBOOT firmware behind RouterOS |

---

## Findings

### F-01 — SSH reachable from WAN; brute force and an unconfirmed successful login

- **Category:** Exposure / Authentication
- **Event type:** Brute force; possible unauthorized access
- **Source IP:port:** 203.0.113.45 (ephemeral ports)
- **Destination IP:port:** 192.0.2.1:22
- **Protocol / service:** TCP / SSH
- **First seen / last seen:** 2026-11-11 02:11:04 / 02:31:19 (+07:00)
- **Evidence:**
  - `/ip/service/print` shows `ssh` enabled with no `available-from` restriction.
  - The input chain accepts TCP/22 from `in-interface-list=WAN` (rule comment "allow SSH").
  - `/log/print where message~"login failure"` shows 412 failures from 203.0.113.45 across 37 usernames between 02:11:04 and 02:29:31.
  - At 02:31:19, the log shows `user admin logged in from 203.0.113.45 via ssh`.
  - No remote syslog; the evidence comes from the volatile memory buffer.
- **Reasoning:** The failure rate, username diversity, and single source are consistent with brute force/password spraying. The successful login from the same source 1m48s after the last failure is a failure→success pivot, the strongest single indicator of possible credential compromise. However, the owner has not confirmed whether the login was legitimate (for example, an administrator using a VPN egress), and no post-login configuration changes were observed in the available buffer.
- **Impact:** If unauthorized, an attacker with admin access can read the full configuration, change routing/DNS/firewall/NAT, create users and scripts, intercept traffic, and use the router as a pivot.
- **Risk:** **HIGH**
- **Confidence:** **MEDIUM** for unauthorized access; **HIGH** that the failures and the successful login occurred.
- **Status:** **ATTEMPTED ATTACK** (for the failures) with possible unauthorized access; not confirmed compromise.
- **Recommendation:** Confirm with the owner whether the 02:31 login was legitimate. If not, treat as a compromise: preserve evidence, disable the account, rotate all credentials/keys, review users/scripts/schedulers/firewall, and isolate the management plane. Close SSH on WAN and use WireGuard or another VPN. See F-02 and F-08.

---

### F-02 — RouterOS 7.16.2 is affected by fixed, critical 2026 issues

- **Category:** Vulnerability
- **Event type:** Known vulnerabilities with applicable exposure
- **Source / destination:** Remote, if the relevant service is reachable
- **Protocol / service:** SSH, WebFig, SNMP, bandwidth test, fetch
- **First seen / last seen:** N/A (configuration state)
- **Evidence:**
  - `/system/resource/print`: version 7.16.2 (stable).
  - `/ip/service/print`: `ssh` and `www-ssl` enabled; `ssh` reachable from WAN.
  - MikroTik advisory: CVE-2026-84411 (WebFig) affects <7.24; fixed in 7.24, 7.23.8 long-term, 6.49.23.
  - MikroTik advisory: CVE-2026-67279, CVE-2026-86060, CVE-2026-67276 (SSH) affect versions before 7.24.2/7.23.4/6.49.21.
  - CVE-2026-67281 (WebFig file read) affects 7.20+ before 7.24.2/7.23.4.
- **Reasoning:** The version is inside multiple affected ranges. SSH is exposed to WAN, which satisfies the precondition for the SSH issues. WebFig is enabled; its WAN reachability was not confirmed because the input chain has a drop for WAN except explicitly allowed services, but the rule set should be verified.
- **Impact:** Potential unauthenticated remote code execution, file read including credentials, or authentication bypass, depending on the CVE and exposure. A successful exploit could lead to full router compromise.
- **Risk:** **HIGH** (CRITICAL if WebFig is confirmed reachable from WAN and an unauthenticated RCE applies).
- **Confidence:** **HIGH** for version applicability; **MEDIUM** for WebFig exposure.
- **Status:** **SUSPICIOUS ACTIVITY** (vulnerable state, no exploit evidence).
- **Recommendation:** Upgrade to 7.24.3 or later stable (or 7.23.6+ long-term if the long-term branch is required), after preserving evidence and planning a maintenance window. Until then, close SSH and WebFig on WAN and restrict them to a management network/VPN. Re-check the vendor advisory for the current fixed release.

---

### F-03 — No IPv6 firewall; IPv6 enabled

- **Category:** Firewall
- **Event type:** Missing control / exposure
- **Source / destination:** IPv6 internet to internal hosts
- **Protocol / service:** All IPv6
- **First seen / last seen:** Configuration state
- **Evidence:**
  - `/ipv6/address/print` shows a global unicast address on `ether1` and a delegated prefix on `bridge`.
  - `/ipv6/firewall/filter/print` is empty.
  - `/ipv6/firewall/raw/print` is empty.
- **Reasoning:** IPv6 has no NAT by default. Internal hosts with global addresses are directly reachable unless the forward chain filters them. The IPv4 firewall does not protect IPv6. This is a common and high-impact gap.
- **Impact:** Direct inbound reachability to internal hosts; exposure of services that were assumed to be "behind NAT"; potential lateral movement.
- **Risk:** **HIGH**
- **Confidence:** **HIGH**
- **Status:** **SUSPICIOUS ACTIVITY** (weakness, not an observed attack).
- **Recommendation:** Add an IPv6 input/forward policy equivalent to IPv4: accept established/related, drop invalid, accept ICMPv6 essentials, allow management only from the management prefix, drop the rest. Verify DHCPv6-PD requirements before filtering.

---

### F-04 — DNS resolver open to WAN

- **Category:** DNS
- **Event type:** Configuration weakness / possible amplification
- **Source / destination:** Any internet source to 192.0.2.1:53
- **Protocol / service:** UDP/TCP 53
- **First seen / last seen:** Configuration state
- **Evidence:**
  - `/ip/dns/print`: `allow-remote-requests: yes`.
  - Input chain has an accept rule for UDP/TCP 53 from `in-interface-list=WAN` (comment "allow DNS").
  - No rate limit on DNS.
- **Reasoning:** An open resolver can be used in DNS amplification/reflection attacks. The router answers queries from any source that can reach port 53. The rule appears intentional but has no source restriction.
- **Impact:** The router can be abused to amplify attacks against third parties, causing reputational, legal, and bandwidth impact; it can also be used for reconnaissance.
- **Risk:** **HIGH**
- **Confidence:** **HIGH**
- **Status:** **SUSPICIOUS ACTIVITY** (configuration weakness).
- **Recommendation:** Remove the WAN accept for 53. Allow DNS only from LAN/VPN. If an external resolver is required, restrict it to specific client addresses and rate-limit. Monitor outbound UDP/53 volume.

---

### F-05 — Unrestricted RDP port forward to a workstation

- **Category:** Firewall / NAT
- **Event type:** Exposure
- **Source / destination:** Any WAN source to 192.0.2.1:3389 → 192.168.88.50:3389
- **Protocol / service:** TCP / RDP
- **First seen / last seen:** Configuration state
- **Evidence:**
  - `/ip/firewall/nat/print` shows `chain=dstnat protocol=tcp dst-port=3389 action=dst-nat to-addresses=192.168.88.50`.
  - The corresponding forward rule accepts the traffic without a source restriction.
  - No account lockout or RDP gateway is in place.
- **Reasoning:** Exposing RDP directly to the internet is a well-known ransomware and brute-force vector. The destination is a workstation, not a hardened terminal server. There is no source allowlist.
- **Impact:** Credential brute force, exploitation of RDP vulnerabilities, ransomware deployment, lateral movement.
- **Risk:** **HIGH**
- **Confidence:** **HIGH**
- **Status:** **SUSPICIOUS ACTIVITY** (exposure, no observed compromise).
- **Recommendation:** Remove the forward. Require VPN for remote desktop. If RDP must be exposed, restrict source addresses, enforce MFA/Network Level Authentication, patch the host, and monitor failed logons on the endpoint.

---

### F-06 — UPnP and SOCKS enabled

- **Category:** Services
- **Event type:** Unnecessary attack surface
- **Source / destination:** LAN to router
- **Protocol / service:** UPnP (TCP/2828, UDP/1900), SOCKS (TCP/1080)
- **First seen / last seen:** Configuration state
- **Evidence:**
  - `/ip/upnp/print`: `enabled: yes`.
  - `/ip/socks/print`: `enabled: yes`.
  - No documented business requirement in the supplied notes.
- **Reasoning:** UPnP lets LAN applications create dynamic NAT mappings without administrator review. SOCKS can be abused as a proxy/pivot if reachable or weakly authenticated. Both increase attack surface.
- **Impact:** Unreviewed inbound exposure; proxy abuse; policy bypass.
- **Risk:** **MEDIUM**
- **Confidence:** **HIGH**
- **Status:** **SUSPICIOUS ACTIVITY** (weakness).
- **Recommendation:** Disable both unless a documented requirement exists. If SOCKS is required, restrict connections and require authentication; review active connections.

---

### F-07 — Shared `admin` account; no source restriction

- **Category:** Users
- **Event type:** Weak identity / accountability
- **Source / destination:** N/A
- **Protocol / service:** All management
- **First seen / last seen:** Configuration state
- **Evidence:**
  - `/user/print`: one active `admin` account in group `full`, no `address` restriction.
  - `/user/active/print`: two concurrent sessions from 192.0.2.10 and 192.0.2.11 at audit time.
  - No individual named accounts.
- **Reasoning:** A shared full-privilege account prevents attribution. There is no way to tell which administrator made a change. The account is also the default target for brute force.
- **Impact:** Weak accountability, credential sharing, inability to revoke one person's access, higher impact if the password leaks.
- **Risk:** **MEDIUM**
- **Confidence:** **HIGH**
- **Status:** **SUSPICIOUS ACTIVITY** (weakness; relates to F-01).
- **Recommendation:** Create individual accounts with least-privilege groups, disable/rename the shared `admin`, restrict source addresses, and use SSH keys. Keep at least one break-glass account with a strong unique password stored securely.

---

### F-08 — No remote syslog; volatile 1000-entry buffer

- **Category:** Logs
- **Event type:** Visibility gap
- **Source / destination:** N/A
- **Protocol / service:** Logging
- **First seen / last seen:** Configuration state
- **Evidence:**
  - `/system/logging/action/print`: only `memory` and `echo` actions; no `remote` server configured.
  - `/system/logging/print`: default topics only.
  - `/log/print`: oldest entry is 2026-11-10 22:58; uptime is 2d4h.
  - No disk logging action.
- **Reasoning:** The default buffer keeps about 1000 entries and loses them on reboot. The F-01 investigation already depends on a partial buffer. Without remote logging, future incidents may be unreconstructable.
- **Impact:** Inability to detect or investigate brute force, configuration changes, or persistence; evidence loss on reboot.
- **Risk:** **MEDIUM**
- **Confidence:** **HIGH**
- **Status:** **SUSPICIOUS ACTIVITY** (control gap).
- **Recommendation:** Configure a remote syslog/SIEM destination over TLS where possible, send `info`, `warning`, `error`, `critical`, and `account`; keep the router clock synchronized; define retention; alert on failure→success and configuration changes.

---

### F-09 — FastTrack placed before the blocklist rule

- **Category:** Firewall
- **Event type:** Control bypass for established flows
- **Source / destination:** Forwarded traffic
- **Protocol / service:** TCP/UDP
- **First seen / last seen:** Configuration state
- **Evidence:**
  - `/ip/firewall/filter/print` order: `fasttrack-connection` (established,related) at position 0; a `drop src-address-list=blocklist` rule at position 6.
  - `/ip/firewall/filter/print stats` shows the FastTrack dummy rule handling the majority of forwarded packets.
- **Reasoning:** FastTracked packets bypass later filter rules. An address added to `blocklist` after its connection is fasttracked will not be blocked until the connection ends or is removed from conntrack.
- **Impact:** A blocklist may appear to work for new connections but fail for existing ones; incident response blocking can be ineffective.
- **Risk:** **MEDIUM**
- **Confidence:** **HIGH**
- **Status:** **SUSPICIOUS ACTIVITY** (weakness).
- **Recommendation:** Place blocklist/drop rules before FastTrack, or remove affected conntrack entries when blocking (an operational change, not read-only). Document the trade-off between performance and inspection.

---

### F-10 — RouterBOOT firmware behind RouterOS

- **Category:** System
- **Event type:** Maintenance
- **Source / destination:** N/A
- **Protocol / service:** RouterBOOT
- **First seen / last seen:** Configuration state
- **Evidence:**
  - `/system/routerboard/print`: `current-firmware: 7.13`, `upgrade-firmware: 7.13`; RouterOS is 7.16.2.
- **Reasoning:** RouterBOOT and RouterOS are separate. The firmware is older than the running RouterOS. This is a maintenance gap, not by itself an exploitable vulnerability. Some hardware fixes require a RouterBOOT upgrade and a reboot.
- **Impact:** Potential hardware/boot fixes missing; upgrade planning required.
- **Risk:** **LOW**
- **Confidence:** **HIGH**
- **Status:** **SUSPICIOUS ACTIVITY** (maintenance observation).
- **Recommendation:** Include RouterBOOT upgrade in the next maintenance window, after verifying the model-specific procedure and rollback. Do not reboot in read-only mode.

---

## Recommendations (prioritized)

### Immediate (0–7 days)

1. Confirm whether the 02:31 SSH login from 203.0.113.45 was authorized. If not, treat as a compromise and preserve evidence before changes.
2. Close SSH (and WebFig/API if not needed) on WAN; require VPN for management.
3. Remove the WAN DNS accept for port 53.
4. Remove the RDP port forward; require VPN.
5. Preserve logs and current configuration evidence; do not reboot.

### Short term (30 days)

6. Upgrade RouterOS to 7.24.3+ stable (or 7.23.6+ long-term) after a change plan.
7. Add a complete IPv6 firewall policy.
8. Disable UPnP and SOCKS.
9. Create individual administrator accounts with least privilege; disable/rename shared `admin`.
10. Configure remote syslog/SIEM and alerting.
11. Move blocklist/drop rules before FastTrack.

### Structural (90 days)

12. Segment management, users, guests, IoT, and servers with VLANs and inter-VLAN filtering.
13. Establish a patching cadence and CVE review process.
14. Add NetFlow/sFlow and an IDS for threats RouterOS cannot see.
15. Document a tested incident-response and recovery plan.
16. Review RouterBOOT firmware and hardware lifecycle.

---

## Items Requiring Further Investigation

- Whether 203.0.113.45 is a known administrator/VPN egress or a hostile source.
- Whether the 02:31 session created any objects (users, scripts, schedulers, firewall/NAT/DNS changes).
- Whether WebFig (443) is reachable from WAN despite the current rule set.
- Whether the RDP host shows failed-logon or malware activity.
- Whether DNS amplification traffic has been observed upstream.
- Whether IPv6 hosts have been scanned or accessed from the internet.

---

## Executive Summary

**English:** The router `edge-rtr` is running RouterOS 7.16.2, which is affected by multiple critical issues fixed in 7.24.x/7.23.x. SSH is reachable from the internet and shows a sustained brute-force campaign (412 failures across 37 usernames) followed by a successful `admin` login from the same address. The owner has not confirmed whether that login was legitimate, so the device is rated SUSPICIOUS rather than CONFIRMED. Separate high-risk weaknesses include an open DNS resolver, no IPv6 firewall, and an unrestricted RDP port forward. Immediate priorities are to confirm or refute the login, close WAN management and DNS, remove the RDP exposure, preserve evidence, and upgrade to a fixed RouterOS release.

**ไทย:** เราเตอร์ `edge-rtr` ใช้ RouterOS 7.16.2 ซึ่งได้รับผลกระทบจากช่องโหว่รุนแรงหลายรายการที่แก้ไขแล้วในเวอร์ชัน 7.24.x/7.23.x พบการเปิด SSH จากอินเทอร์เน็ตและมี brute force 412 ครั้งจาก 37 ชื่อผู้ใช้ ตามด้วยการ login สำเร็จของบัญชี `admin` จาก IP เดียวกัน แต่ยังไม่ได้รับการยืนยันว่าเป็นการ login ของผู้ดูแลจริง จึงจัดสถานะเป็น “น่าสงสัย” ไม่ใช่ “ยืนยันว่าถูกบุกรุก” นอกจากนี้ยังพบ DNS resolver เปิดให้ภายนอก, ไม่มี firewall IPv6 และเปิด port forward RDP โดยไม่มีข้อจำกัด ควรยืนยันเหตุการณ์ login, ปิด SSH/DNS/RDP จาก WAN, เก็บหลักฐาน และอัปเกรดเป็นเวอร์ชันที่แก้ไขแล้วโดยเร็ว

---

## Limitations and Evidence Gaps

- No remote syslog; the memory buffer may have rotated and cannot prove absence of earlier events.
- The successful login was not confirmed as legitimate or illegitimate by the owner.
- No packet capture, NetFlow, IDS, endpoint, or switch data was available.
- WebFig WAN reachability was inferred from configuration, not tested externally (active testing is out of scope).
- Vulnerability applicability is based on version and advisory data as of 2026-11-11; re-check before remediation.
- IPv6 host exposure was not enumerated.
- RouterOS conntrack is a snapshot; no historical flow analysis was possible.
- The audit did not perform penetration testing or exploitation.

---

## Appendix — Key commands used

```ros
/system/resource/print
/system/routerboard/print
/system/package/print
/system/clock/print
/ip/service/print
/ip/ssh/print
/user/print
/user/group/print
/user/active/print
/ip/firewall/filter/print
/ip/firewall/filter/print stats
/ip/firewall/nat/print
/ip/firewall/address-list/print
/ip/firewall/connection/tracking/print
/ip/dns/print
/ip/upnp/print
/ip/socks/print
/ipv6/address/print
/ipv6/firewall/filter/print
/log/print
/system/logging/print
/system/logging/action/print
```

All commands were read-only. No configuration was changed.

---

## Sources

- MikroTik security announcements: <https://mikrotik.com/supportsec>
- CISA ICSA-26-272-06: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-272-06>
- NVD: <https://nvd.nist.gov/>
- Securing your router: <https://manual.mikrotik.com/docs/getting-started/securing-your-router>
- Services: <https://manual.mikrotik.com/docs/system-information-and-utilities/services>
- Firewall: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall>
- DNS: <https://manual.mikrotik.com/docs/network-management/dns>
- Log: <https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log>
- User policies: <https://manual.mikrotik.com/docs/authentication-authorization-accounting/user>
- NIST CSF 2.0: <https://www.nist.gov/cyberframework>
