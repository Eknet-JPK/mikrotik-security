# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-11-11

### Added

- OpenCode skill entry point `SKILL.md` with:
  - strict read-only operating contract;
  - ten-step incident workflow;
  - evidence and confidence standards;
  - risk rating guide;
  - required audit report structure;
  - Thai user-facing guidance;
  - optional EKNET Hotspot integration rules.
- Fourteen technical references:
  - `references/routeros-architecture.md` — RouterOS model, packages, interfaces, services, v6/v7 differences.
  - `references/routeros-api.md` — API/REST protocol, safe read patterns, allowlisting, credential handling.
  - `references/firewall-security.md` — filter, RAW, NAT, mangle, address lists, conntrack, FastTrack, defconf.
  - `references/network-security.md` — TCP/UDP/ICMP, DNS, ARP, VLAN, NAT, VPN, management plane, NAC.
  - `references/brute-force-detection.md` — authentication logs, heuristics, correlation, false positives.
  - `references/port-scanning-detection.md` — scan types, native artifacts, thresholds, limitations.
  - `references/ddos-detection.md` — floods, amplification, conntrack exhaustion, evidence standards.
  - `references/ssh-winbox-api-security.md` — management-service exposure, logs, hardening.
  - `references/security-log-analysis.md` — topics, formats, time handling, correlation, timelines.
  - `references/network-traffic-analysis.md` — counters, conntrack, baselines, C2/exfil indicators.
  - `references/vulnerability-assessment.md` — CVE applicability method and 2025–2026 advisory snapshot.
  - `references/incident-investigation.md` — evidence preservation, ten-step investigation, containment.
  - `references/security-audit-framework.md` — categories, checks, severity, confidence, reporting.
  - `references/read-only-safety.md` — permitted/prohibited operations, read-only account, API allowlist.
- Three synthetic examples:
  - `examples/sample-security-logs.md`
  - `examples/sample-attack-patterns.md`
  - `examples/sample-audit-report.md`
- `README.md` with installation, usage, structure, safety, and limitations.
- MIT `LICENSE` and `.gitignore` for credentials and local artifacts.

### Security

- Default mode is strict read-only; no router was contacted during authoring.
- No credentials, keys, tokens, or real router data are included.
- Synthetic data uses RFC 5737 addresses and RFC 7042 MAC addresses.
- Documents the difference between behavioral safeguards and technical enforcement.
- Recommends a dedicated read-only RouterOS group and an allowlisting API proxy.

### Verified technical baseline

- OpenCode V2 skill convention: directory-form `SKILL.md`, ID derived from directory name, `description` required for discovery.
- MikroTik RouterOS 7.26 manual (current at review date) and frozen legacy docs.
- MikroTik security advisories current to 2026-11-11, including CVE-2026-84411, CVE-2026-67279, CVE-2026-67281, CVE-2026-67278, CVE-2026-88464, CVE-2026-98432, CVE-2025-42611, CVE-2025-6443.
- CISA ICSA-26-272-06 and NVD records.

### Known limitations

- CVE and fixed-version data changes frequently; re-verify before each assessment.
- RouterOS logs are volatile by default; absence of evidence is not proof of absence.
- Layer-2 threats, payload-level C2, and endpoint compromise require external evidence.
- The skill cannot remediate; it recommends and reports.

## [Unreleased]

- Planned: additional synthetic case studies for IPv6 exposure and VPN credential attacks.
- Planned: example read-only API proxy configuration.
