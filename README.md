# mikrotik-security

An independent, production-oriented **OpenCode Skill** for MikroTik RouterOS security analysis: read-only audits, firewall review, attack detection, log analysis, traffic analysis, CVE assessment, incident investigation, and professional reporting.

> **Safety first:** the skill operates in **STRICT READ-ONLY MODE** by default. It does not add, change, delete, reboot, export, or upgrade anything. See [`references/read-only-safety.md`](references/read-only-safety.md).

- **Skill ID:** `mikrotik-security`
- **Version:** 1.0.0
- **Last reviewed:** 2026-11-11
- **License:** MIT

---

## 1. What it does

| Capability | Reference |
|---|---|
| RouterOS architecture, v6/v7 differences, services, packages | `references/routeros-architecture.md` |
| Safe API/REST access with allowlisting | `references/routeros-api.md` |
| Firewall filter/RAW/NAT/mangle review | `references/firewall-security.md` |
| TCP/IP, DNS, ARP, VLAN, NAT, VPN fundamentals | `references/network-security.md` |
| SSH/WinBox/API/FTP/VPN brute-force detection | `references/brute-force-detection.md` |
| Port scanning and service enumeration | `references/port-scanning-detection.md` |
| DoS/DDoS, floods, connection exhaustion | `references/ddos-detection.md` |
| Management-service exposure and hardening | `references/ssh-winbox-api-security.md` |
| Log fields, topics, correlation, timelines | `references/security-log-analysis.md` |
| Connection tracking and traffic baselines | `references/network-traffic-analysis.md` |
| CVE applicability and vulnerability assessment | `references/vulnerability-assessment.md` |
| Incident investigation workflow | `references/incident-investigation.md` |
| Audit categories, severity, scoring, reporting | `references/security-audit-framework.md` |
| The read-only contract | `references/read-only-safety.md` |

It explains **why** a finding matters, separates **confirmed incidents** from **suspicious activity** and **insufficient evidence**, and never claims a router is compromised without evidence.

---

## 2. Installation

OpenCode discovers directory-form skills at `SKILL.md` under a skills source root. The skill ID comes from the directory name, so the directory **must** be named `mikrotik-security`.

### Global (recommended)

```bash
mkdir -p ~/.config/opencode/skills
git clone https://github.com/Eknet-JPK/mikrotik-security.git \
  ~/.config/opencode/skills/mikrotik-security
```

### Project-local

```bash
mkdir -p .opencode/skills
git clone https://github.com/Eknet-JPK/mikrotik-security.git \
  .opencode/skills/mikrotik-security
```

### Manual

Copy the repository so that this file exists:

```text
~/.config/opencode/skills/mikrotik-security/SKILL.md
```

Do not nest it one level deeper; OpenCode will derive a different ID.

OpenCode V2 reloads skills when files change. If discovery does not refresh, run `/reload` in the TUI. No restart is required.

### Verify discovery

```bash
ls ~/.config/opencode/skills/mikrotik-security/SKILL.md
head -8 ~/.config/opencode/skills/mikrotik-security/SKILL.md
```

The frontmatter must contain a `description`; otherwise the model will not be shown the skill.

---

## 3. Usage

Mention the skill by ID:

```text
@mikrotik-security
```

Or ask naturally; the description lets OpenCode advertise it.

### Security audit (Thai)

```text
@mikrotik-security
ตรวจสอบความปลอดภัยเราเตอร์ MikroTik 192.168.1.1
ระบุการโจมตี กิจกรรมน่าสงสัย และจุดอ่อนด้านความปลอดภัย
ใช้โหมดอ่านอย่างเดียวเท่านั้น (STRICT READ-ONLY MODE)
สรุปเป็นภาษาไทย
```

### Brute-force analysis

```text
@mikrotik-security
Analyze the MikroTik authentication logs.
Identify failed logins and potential brute-force attacks.
List source IP addresses, targeted accounts, and a timeline.
Do not change anything.
```

### DDoS triage

```text
@mikrotik-security
Analyze connection tracking and interface counters.
Determine whether there are indicators of DoS or DDoS activity.
Explain the evidence and the confidence level. Do not claim a DDoS
without sufficient evidence.
```

### Firewall review

```text
@mikrotik-security
Review the MikroTik firewall (filter, RAW, NAT).
Identify weaknesses and recommend improvements.
Do not modify any configuration.
```

### Multi-router audit

```text
@mikrotik-security
Audit all authorized MikroTik routers available in the connected environment.
Generate a separate report per router and a fleet summary.
Use STRICT READ-ONLY MODE.
```

### Offline review

```text
@mikrotik-security
Here is a sanitized configuration and a log excerpt. Perform an offline
security review. Label it as not verified against the live device.
```

---

## 4. Read-only enforcement

The skill allows only verified read operations. It prohibits:

- `add`, `set`, `remove`, `enable`, `disable`, `reset`, `clear`;
- `export`, backup, restore, import;
- reboot, shutdown, reset-configuration;
- package/routerboard upgrades, `check-for-updates`;
- `/tool fetch`, ping, traceroute, torch, sniffer, bandwidth-test, traffic-generator;
- creating files on the router, including `/log print file=...`;
- user/password/script/scheduler/firewall/NAT/DNS/route changes;
- clearing logs or counters;
- any script, container, or command execution.

**Important:** instructions are not a technical permission boundary. A `full` RouterOS account can still do anything. For real protection, use:

1. a dedicated read-only RouterOS account, and
2. a read-only API proxy with an allowlist.

Recommended group (the router owner applies it, not this skill):

```ros
/user/group/add name=security-audit policy=read,api,rest-api,ssh,winbox,web
/user/add name=sec-auditor group=security-audit password="<strong>" address=192.0.2.0/24
```

The built-in `read` group is **not** safe: it still includes `reboot` and `sensitive`.

Never place credentials in prompts, files, git, reports, or logs. See `references/read-only-safety.md`.

---

## 5. Repository structure

```text
mikrotik-security/
├── SKILL.md
├── README.md
├── CHANGELOG.md
├── LICENSE
├── .gitignore
├── references/
│   ├── routeros-architecture.md
│   ├── routeros-api.md
│   ├── firewall-security.md
│   ├── network-security.md
│   ├── brute-force-detection.md
│   ├── port-scanning-detection.md
│   ├── ddos-detection.md
│   ├── ssh-winbox-api-security.md
│   ├── security-log-analysis.md
│   ├── network-traffic-analysis.md
│   ├── vulnerability-assessment.md
│   ├── incident-investigation.md
│   ├── security-audit-framework.md
│   └── read-only-safety.md
└── examples/
    ├── sample-security-logs.md
    ├── sample-attack-patterns.md
    └── sample-audit-report.md
```

`SKILL.md` is the entry point. References are loaded on demand; they are not all injected into every prompt.

---

## 6. Optional EKNET Hotspot integration

This skill is independent. It does not require EKNET Hotspot and does not modify it.

If the user explicitly asks to audit routers registered in EKNET Hotspot **and** the `eknet-hotspot` skill/integration is actually available:

- `@eknet-hotspot` finds routers, opens the existing database, retrieves/decrypts credentials in memory, and exposes its existing RouterOS API layer.
- `@mikrotik-security` performs the analysis and reporting.

Rules:

1. Reuse the existing API layer; do not build a second credential path.
2. Never display, log, or store decrypted passwords, keys, or tokens.
3. Do not create credentials or accounts unnecessarily.
4. Do not modify EKNET Hotspot, its database, or its config.
5. Apply the same read-only allowlist to calls through that layer.
6. If the integration is unavailable, use a supplied read-only account, configuration, or logs.

Do not assume the integration exists. Verify it first.

---

## 7. Evidence and reporting

Every audit uses the structure in `SKILL.md` and `references/security-audit-framework.md`:

- Router information and read-only enforcement method;
- Security status: `NORMAL` / `SUSPICIOUS` / `CONFIRMED` / `INSUFFICIENT DATA`;
- Findings with evidence, reasoning, impact, risk, confidence, and status;
- Prioritized recommendations;
- Items requiring further investigation;
- Executive summary (Thai supported);
- Limitations and evidence gaps.

Risk: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`.
Confidence: `HIGH` / `MEDIUM` / `LOW`.
Status: `ATTEMPTED ATTACK` / `SUSPICIOUS ACTIVITY` / `UNAUTHORIZED ACCESS` / `CONFIRMED COMPROMISE` / `INSUFFICIENT EVIDENCE`.

Absence of logs is never treated as proof that no attack occurred.

---

## 8. Version and source policy

- RouterOS v6 and v7 are both covered, with explicit differences.
- RAW firewall: v6.36+ and v7.
- REST API, WireGuard, containers, `/system/history`: v7.
- CVE data is a verified snapshot dated **2026-11-11**; always re-check the vendor advisory before reporting a live device as vulnerable.
- Primary sources: MikroTik manual (<https://manual.mikrotik.com/>), MikroTik security (<https://mikrotik.com/supportsec>), NVD, CVE.org, CISA, MITRE ATT&CK, NIST CSF 2.0, OWASP.

If a fact cannot be verified, the skill states the limitation rather than inventing a command or finding.

---

## 9. Verification (no router contact)

```bash
# Structure
find . -maxdepth 2 -type f | sort

# Frontmatter and skill ID
head -8 SKILL.md

# No obvious secrets
grep -RInE '(password|passwd|secret|token|api[_-]?key|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY)' \
  --include='*.md' . | grep -v '<strong>' | grep -v 'password-authentication' || true

# Links (sample; requires network)
grep -Rho 'https://[^)> ]*' references SKILL.md | sort -u | head
```

Do not connect to a real router, run scans, or perform penetration testing as part of installation verification.

---

## 10. Limitations

- No payload inspection, endpoint forensics, or memory analysis.
- RouterOS logs are small and volatile by default; absence of evidence is not evidence of absence.
- Connection tracking is a snapshot, not a historical flow record.
- ARP spoofing, rogue DHCP, and many Layer-2 attacks need switch/IDS evidence.
- NAT and proxies obscure source attribution.
- The skill cannot prove intent or botnet distribution from RouterOS data alone.
- CVE applicability depends on version, feature, and exposure; an old version is not automatically vulnerable.
- The skill does not remediate. It recommends; the owner applies changes.

---

## 11. Contributing

- Keep the read-only contract intact.
- Cite official sources and include a "Last reviewed" date.
- Label synthetic examples clearly.
- Do not include real router configs, logs, credentials, or customer data.
- Prefer precise, version-aware commands over generic advice.
- Test documentation changes for broken links and stale CVE data.

---

## 12. License

MIT. See [`LICENSE`](LICENSE).

MikroTik, RouterOS, RouterBOARD, and WinBox are trademarks of MikroTik SIA. This project is independent and not affiliated with or endorsed by MikroTik.
