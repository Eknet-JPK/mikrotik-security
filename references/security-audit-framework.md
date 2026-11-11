# MikroTik Security Audit Framework

**Scope:** A repeatable, evidence-based audit method for one router or a fleet.
**Last reviewed:** 2026-11-11
**Applies to:** RouterOS v6 and v7. Commands may need version adjustments.

---

## 1. Audit principles

- **Read-only.** No configuration changes, reboots, exports, or active testing.
- **Evidence-first.** Every finding cites a command output, log entry, counter, or supplied document.
- **Applicability over checklists.** A checklist item that does not apply is marked N/A, not "pass".
- **Severity = impact × likelihood × exposure.** A CVSS score alone is not a severity.
- **Confidence is separate from severity.** You can have a HIGH-severity, LOW-confidence finding.
- **No finding without verification.** "Looks suspicious" is an observation, not a finding.
- **State limitations.** Missing logs, disabled features, and offline data change what can be concluded.

---

## 2. Categories and assessment items

### 2.1 Authentication

| ID | Check | Evidence | Fail condition | Severity |
|---|---|---|---|---|
| AUTH-01 | Failed login volume and sources | `/log/print where message~"login failure"` | Sustained failures from untrusted sources | HIGH |
| AUTH-02 | Success after failure | Correlate `login failure` and `logged in` | Success from a source with prior failures, unexplained | CRITICAL/HIGH |
| AUTH-03 | Rate limiting / lockout | `/ip/firewall/address-list/print`, filter rules | No rate limiting on exposed auth services | MEDIUM |
| AUTH-04 | Password policy | `/user/settings/print` | Weak minimum length/categories | MEDIUM |
| AUTH-05 | SSH key usage | `/user/ssh-keys/print`, `/ip/ssh/print` | Password-only auth on exposed SSH | MEDIUM |
| AUTH-06 | VPN authentication | `/ppp/secret/print`, IPsec/WireGuard config | Weak/shared credentials, no MFA | HIGH |
| AUTH-07 | Default admin name | `/user/print` | `admin` active with a weak/known password | HIGH |
| AUTH-08 | Shared accounts | `/user/print`, `/user/active/print` | Multiple people share one account | MEDIUM |

### 2.2 Firewall

| ID | Check | Evidence | Fail condition | Severity |
|---|---|---|---|---|
| FW-01 | Input default deny | `/ip/firewall/filter/print where chain=input` | No final drop or broad accept | CRITICAL |
| FW-02 | Forward default deny | `/ip/firewall/filter/print where chain=forward` | Unrestricted forwarding from WAN | HIGH |
| FW-03 | Rule order | `print` | Drop shadowed by earlier accept | HIGH |
| FW-04 | Disabled critical rules | `print` | `X` on a necessary drop | HIGH |
| FW-05 | Invalid state drop | `print where connection-state=invalid` | No invalid drop | MEDIUM |
| FW-06 | IPv6 parity | `/ipv6/firewall/filter/print` | IPv6 enabled without filter | HIGH |
| FW-07 | RAW table | `/ip/firewall/raw/print` | No early bogon/flood controls (optional) | LOW/INFO |
| FW-08 | FastTrack placement | `print where action=fasttrack-connection` | FastTrack before blocklist/security rules | MEDIUM |
| FW-09 | Logging | `print`, `/system/logging/print` | No security-relevant logging | MEDIUM |
| FW-10 | NAT exposure | `/ip/firewall/nat/print` | Unrestricted dst-nat to sensitive host | HIGH |
| FW-11 | UPnP | `/ip/upnp/print` | Enabled without need | MEDIUM |
| FW-12 | Interface list integrity | `/interface/list/member/print` | WAN interface not in WAN list | HIGH |

### 2.3 Services

| ID | Check | Evidence | Fail condition | Severity |
|---|---|---|---|---|
| SVC-01 | Service inventory | `/ip/service/print` | Unused Telnet/FTP/HTTP/API enabled | MEDIUM |
| SVC-02 | Source restriction | `print` | Management reachable from WAN | CRITICAL |
| SVC-03 | TLS certificates | `/ip/service/print`, `/certificate/print` | WebFig/API-SSL without valid cert | MEDIUM |
| SVC-04 | MAC server | `/tool/mac-server/print` | MAC-Telnet/WinBox open on WAN/LAN broadly | MEDIUM |
| SVC-05 | RoMON | `/tool/romon/print` | Enabled without need | MEDIUM |
| SVC-06 | SNMP | `/snmp/print`, `/snmp/community/print` | v1/v2c public/private, WAN reachable | HIGH |
| SVC-07 | Cloud/DDNS | `/ip/cloud/print` | Unintended public DNS name/Back To Home | MEDIUM |
| SVC-08 | Discovery | `/ip/neighbor/discovery-settings/print` | MNDP/CDP/LLDP on WAN | LOW |
| SVC-09 | Reverse proxy/containers | `/ip/service/print`, `/container/print` | Unreviewed exposed service | MEDIUM |

### 2.4 Users and permissions

| ID | Check | Evidence | Fail condition | Severity |
|---|---|---|---|---|
| USR-01 | User inventory | `/user/print` | Unknown/stale accounts | HIGH |
| USR-02 | Group policies | `/user/group/print` | Admin group overused; `read` used as "safe" | MEDIUM |
| USR-03 | Least privilege | `print` | Auditors with `full` | MEDIUM |
| USR-04 | Source restriction | `/user/print` | No `address` restriction for admins | MEDIUM |
| USR-05 | SSH keys | `/user/ssh-keys/print` | Unknown keys, weak RSA exponent | HIGH |
| USR-06 | Active sessions | `/user/active/print` | Unexpected session/source | HIGH |
| USR-07 | Inactivity policy | `/user/print` | No timeout on admin sessions | LOW |
| USR-08 | Password expiry/complexity | `/user/settings/print` | Disabled entirely | LOW/MEDIUM |

### 2.5 Network

| ID | Check | Evidence | Fail condition | Severity |
|---|---|---|---|---|
| NET-01 | Interface inventory | `/interface/print` | Unknown/rogue interface | MEDIUM |
| NET-02 | Bridge/VLAN design | `/interface/bridge/print`, `/interface/bridge/vlan/print` | Flat network, guest bridged to LAN | HIGH |
| NET-03 | Inter-VLAN filtering | `/ip/firewall/filter/print` | Unfiltered routing between trust zones | HIGH |
| NET-04 | DHCP | `/ip/dhcp-server/print`, `/ip/dhcp-server/lease/print` | DHCP server on WAN, rogue DHCP risk | HIGH |
| NET-05 | ARP | `/ip/arp/print` | Duplicate MAC/gateway changes | MEDIUM (needs corroboration) |
| NET-06 | Conntrack capacity | `/ip/firewall/connection/tracking/print` | Near max-entries | MEDIUM |
| NET-07 | Wireless security | `/interface/wireless/security-profiles/print` or `/interface/wifi/security/print` | WEP/open/weak PSK/WPS | HIGH |
| NET-08 | VPN design | WireGuard/IPsec/PPP config | PPTP, L2TP without IPsec, weak ciphers | HIGH |
| NET-09 | Segmentation of management | VLAN/interface design | Management reachable from user VLANs | HIGH |

### 2.6 Routing

| ID | Check | Evidence | Fail condition | Severity |
|---|---|---|---|---|
| RT-01 | Default route | `/ip/route/print` | Unexpected gateway | CRITICAL if unauthorized |
| RT-02 | Static routes | `print` | Unknown route/blackhole | HIGH |
| RT-03 | Policy routing | `/routing/rule/print` (v7) | Unknown rule redirecting traffic | HIGH |
| RT-04 | Routing protocol auth | BGP/OSPF config | No authentication/prefix filters | MEDIUM/HIGH |
| RT-05 | Route changes | `/system/history/print` | Unauthorized change | HIGH |
| RT-06 | Failover correctness | `print` | Asymmetric routing or loops | LOW/MEDIUM |

### 2.7 DNS

| ID | Check | Evidence | Fail condition | Severity |
|---|---|---|---|---|
| DNS-01 | Open resolver | `/ip/dns/print`, firewall 53 | `allow-remote-requests=yes` + WAN reachable | HIGH |
| DNS-02 | Static records | `/ip/dns/static/print` | Unknown redirect entries | HIGH |
| DNS-03 | DoH/forwarders | `/ip/dns/print` | Unintended bypass of local DNS policy | MEDIUM |
| DNS-04 | Cache/health | `print` | Cache exhaustion/misconfiguration | LOW |
| DNS-05 | IPv6 DNS exposure | `/ipv6/firewall/filter/print where dst-port=53` | Unfiltered IPv6 DNS | HIGH |

### 2.8 System

| ID | Check | Evidence | Fail condition | Severity |
|---|---|---|---|---|
| SYS-01 | RouterOS version | `/system/resource/print` | Applicable CVE (see §2.11) | varies |
| SYS-02 | RouterBOOT firmware | `/system/routerboard/print` | Mismatch/very old (maintenance) | LOW |
| SYS-03 | Packages | `/system/package/print` | Unused/optional packages | LOW/MEDIUM |
| SYS-04 | Clock/NTP | `/system/clock/print`, `/system/ntp/client/print` | Wrong time, no NTP | MEDIUM (evidence integrity) |
| SYS-05 | Resource pressure | `/system/resource/print` | Sustained high CPU/memory | MEDIUM |
| SYS-06 | Device mode | `/system/device-mode/print` | No restrictions/flagged | MEDIUM/HIGH |
| SYS-07 | License | `/system/license/print` | Expired/limited (operational) | INFO |
| SYS-08 | Containers | `/container/print` | Untrusted images/privileged mounts | HIGH |
| SYS-09 | Certificates | `/certificate/print` | Expired/untrusted CAs | MEDIUM |

### 2.9 Logs and monitoring

| ID | Check | Evidence | Fail condition | Severity |
|---|---|---|---|---|
| LOG-01 | Logging rules | `/system/logging/print` | Missing `account`/`critical` coverage | MEDIUM |
| LOG-02 | Remote syslog | `/system/logging/action/print` | No remote destination | MEDIUM |
| LOG-03 | Retention | action config, buffer size | Too short for incident response | MEDIUM |
| LOG-04 | Clock accuracy | `/system/clock/print` | Unsynchronized | MEDIUM |
| LOG-05 | Critical events | `/log/print where topics~"critical"` | Unexplained failures/reboots | HIGH |
| LOG-06 | Log gaps | uptime/reboot/clear | Gaps without explanation | HIGH (if suspicious) |

### 2.10 Exposure

| ID | Check | Evidence | Fail condition | Severity |
|---|---|---|---|---|
| EXP-01 | WAN management | `/ip/service/print`, filter | WinBox/SSH/API/WebFig reachable | CRITICAL |
| EXP-02 | Port forwards | `/ip/firewall/nat/print` | Unnecessary/sensitive exposure | HIGH |
| EXP-03 | VPN endpoints | IPsec/L2TP/PPTP/OVPN/WireGuard | Weak/legacy VPN exposed | HIGH |
| EXP-04 | Cloud/DDNS | `/ip/cloud/print` | Public name not intended | MEDIUM |
| EXP-05 | UPnP/NAT-PMP | `/ip/upnp/print` | Dynamic exposure | MEDIUM |
| EXP-06 | MAC/RoMON | `/tool/mac-server/print`, `/tool/romon/print` | Layer-2 management open | MEDIUM |
| EXP-07 | SNMP | `/snmp/print` | Public community/WAN reachable | HIGH |
| EXP-08 | Hotspot/guest | `/ip/hotspot/print` | Guest path to management | HIGH |

### 2.11 Vulnerability

| ID | Check | Evidence | Fail condition | Severity |
|---|---|---|---|---|
| VUL-01 | Exact version | `/system/resource/print` | Applicable CVE + exposure | varies |
| VUL-02 | Fixed version known | Vendor advisory | No remediation plan | MEDIUM |
| VUL-03 | Feature exposure | service/firewall config | Vulnerable feature reachable | varies |
| VUL-04 | EOL/unsupported | Vendor lifecycle | Unsupported release | MEDIUM |
| VUL-05 | Package mismatch | `/system/package/print` | Version skew | LOW |
| VUL-06 | Exploit in wild | Vendor/CISA/NVD | Known exploitation + exposure | CRITICAL |

Use `references/vulnerability-assessment.md` for the CVE snapshot and method.

---

## 3. Risk classification

### 3.1 Severity

| Rating | Definition | Examples |
|---|---|---|
| **CRITICAL** | Remote unauthenticated compromise or router-wide control; immediate action required. | Exposed WebFig with an applicable pre-auth RCE; confirmed admin compromise; no input firewall on WAN. |
| **HIGH** | Successful unauthorized access or a material weakness with a realistic path. | Exposed WinBox/SSH/API; unknown admin user; unrestricted dst-nat to management; open resolver. |
| **MEDIUM** | Weakness requiring a precondition or with limited scope. | Missing invalid drop; excessive permissions; no remote logging; weak TLS. |
| **LOW** | Hygiene/maintenance issue with limited security impact. | Old RouterBOOT; unused package; missing rule comments. |
| **INFO** | Observation or improvement. | Documentation gap; optional hardening. |

### 3.2 Likelihood × impact

```text
                 Impact
              Low   Med   High  Critical
Likelihood High  M    H     C      C
           Med   L    M     H      C
           Low   I    L     M      H
```

Exposure and preconditions set likelihood. Do not rate a theoretical issue HIGH without a path.

### 3.3 Confidence

| Level | Test |
|---|---|
| HIGH | Direct evidence + independent corroboration + verified mechanism. |
| MEDIUM | Direct evidence, but a plausible alternative remains. |
| LOW | Indirect/partial evidence; hypothesis. |

### 3.4 Optional heuristic score

If the owner wants a single number, use this **heuristic** (not a standard):

```text
score = 100
for each finding:
    CRITICAL: -25
    HIGH:     -12
    MEDIUM:   -5
    LOW:      -2
    INFO:      0
score = max(0, score)
```

Bands: 90–100 strong; 70–89 acceptable; 50–69 weak; 0–49 critical. Always show the findings behind the number; a score hides nuance.

---

## 4. Audit workflow

### 4.1 Preparation

- Confirm authorization, scope, time window, and data source.
- Obtain a read-only account or offline data.
- Record the change freeze/maintenance context.
- Prepare the evidence folder and report template.
- Do not run active scans or exploitation.

### 4.2 Collection

Use the minimum set in `references/incident-investigation.md` §2. Sample large tables.

Example evidence snapshot (synthetic):

```text
[admin@edge-rtr] > /ip/service/print
Flags: X - DISABLED
Columns: NAME, PORT, ADDRESS
 #   NAME       PORT  ADDRESS
 0   ftp          21
 1   ssh          22  0.0.0.0/0
 2 X telnet       23
 3 X www          80
 4   www-ssl     443  192.0.2.0/24
 5   winbox     8291  192.0.2.0/24
 6 X api        8728
 7   api-ssl    8729  192.0.2.0/24

[admin@edge-rtr] > /ip/firewall/filter/print stats
 #   CHAIN    ACTION   BYTES         PACKETS
 0   input    accept   50 507 925 242  50 048 246
 1   input    drop     432 270          9 719
```

Interpretation: SSH with `0.0.0.0/0` is a finding only if the firewall also permits it from WAN. Verify interface-list membership and rule order before assigning severity.

### 4.3 Analysis

Work category by category. For each item:

1. Run the read.
2. Record the raw evidence.
3. Mark PASS / FAIL / N/A / UNKNOWN.
4. If FAIL, assign severity and confidence.
5. Write the reasoning and impact.
6. Write a specific recommendation.

### 4.4 Validation

- Re-check every FAIL against a second source where possible.
- Confirm the interface list membership and WAN reachability before rating exposure.
- Check the version against the advisory, not memory.
- Ask: "What would make this finding wrong?" If the answer is plausible, lower confidence.

### 4.5 Reporting

Use the required structure in section 5. Separate facts, hypotheses, and missing data.

---

## 5. Required report structure

```markdown
## MikroTik Security Audit Report

### Router Information
- Router Identity:
- Router IP / management address:
- RouterOS version / architecture:
- Board / serial:
- Audit date and time / time zone:
- Data source: live read-only API | supplied config | supplied logs | syslog export
- Connection status:
- Read-only enforcement: dedicated read-only account | full account + allowlist | offline
- Auditor:
- Scope and exclusions:

### Security Status
NORMAL | SUSPICIOUS | CONFIRMED | INSUFFICIENT DATA

### Summary of Findings
| ID | Category | Severity | Confidence | Status | Title |
|---|---|---|---|---|---|

### Findings
#### F-01 — <title>
- Category: Firewall
- Event type:
- Source IP:port:
- Destination IP:port:
- Protocol / service:
- First seen / last seen:
- Evidence:
- Reasoning:
- Impact:
- Risk: CRITICAL | HIGH | MEDIUM | LOW | INFO
- Confidence: HIGH | MEDIUM | LOW
- Status: ATTEMPTED ATTACK | SUSPICIOUS ACTIVITY | UNAUTHORIZED ACCESS | CONFIRMED COMPROMISE | INSUFFICIENT EVIDENCE
- Recommendation:

### Recommendations (prioritized)
1. Immediate (0–7 days)
2. Short term (30 days)
3. Structural (90 days)

### Items Requiring Further Investigation
- 

### Executive Summary
<5–10 sentences, plain language, Thai if requested>

### Limitations and Evidence Gaps
- 

### Appendix
- Commands run
- Raw evidence references
- Version/advisory sources
```

---

## 6. Multi-router audit

For a fleet:

1. Enumerate authorized routers only.
2. Use a per-router read-only account or the approved integration layer.
3. Collect the same baseline from each.
4. Produce one report per router and a fleet summary.
5. Rank by exposure and severity, not by router count.
6. Do not reuse a single credential across unrelated owners without authorization.
7. Rate-limit concurrent collection; avoid CPU spikes on production routers.
8. Record per-router clock/time zone; do not compare timestamps naively.
9. Keep credentials out of reports and logs.
10. If EKNET Hotspot is the source, follow `SKILL.md` §9 — reuse its API layer, never print decrypted secrets, never modify EKNET.

Fleet summary table:

| Router | Version | WAN mgmt exposed | Critical | High | Status | Last seen |
|---|---|---|---|---|---|---|

---

## 7. Offline audit

If you only have a configuration export or logs:

- Label the report "OFFLINE — not verified against the live device".
- You can assess rule logic, users, services, DNS, NAT, and version.
- You cannot verify live counters, active sessions, current exposure, or whether a rule is actually matching.
- Treat absent data as UNKNOWN, not PASS.
- Do not ask for `export show-sensitive`; ask for a sanitized export or specific read outputs.

---

## 8. Evidence quality checklist

- [ ] Source and time of collection recorded.
- [ ] Router clock/time zone recorded.
- [ ] Version and build recorded.
- [ ] Commands and filters recorded.
- [ ] Raw outputs preserved.
- [ ] Counts and windows recorded, not just examples.
- [ ] Alternate explanations considered.
- [ ] Confidence justified.
- [ ] Limitations stated.
- [ ] No credentials or secrets in the report.

---

## 9. Limitations

- The framework is a guide, not a certification.
- Coverage depends on data availability.
- Some categories require external evidence (IDS, switch, EDR, flow).
- RouterOS behavior varies by version and hardware.
- A PASS means "no evidence of failure in the data reviewed", not a guarantee.
- A numeric score is a communication aid, not a risk model.

---

## 10. Sources

- Securing your router: <https://manual.mikrotik.com/docs/getting-started/securing-your-router>
- Services: <https://manual.mikrotik.com/docs/system-information-and-utilities/services>
- Firewall: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall>
- Connection tracking: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/connection-tracking>
- Log: <https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log>
- User policies: <https://manual.mikrotik.com/docs/authentication-authorization-accounting/user>
- MikroTik security: <https://mikrotik.com/supportsec>
- NIST CSF 2.0: <https://www.nist.gov/cyberframework>
- CIS Controls: <https://www.cisecurity.org/controls>
- OWASP: <https://owasp.org/>
