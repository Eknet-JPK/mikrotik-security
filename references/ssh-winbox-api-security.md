# SSH, WinBox, API, and WebFig Security

**Scope:** Assessing and hardening RouterOS management services, and recognizing evidence of their abuse.
**Last reviewed:** 2026-11-11
**Applies to:** RouterOS v6 and v7; service settings vary slightly by release.

---

## 1. The management plane is the primary target

Internet-facing RouterOS devices are continuously scanned for WinBox (8291), SSH (22), API (8728/8729), HTTP/HTTPS (80/443), Telnet (23), and FTP (21). A reachable management service gives an attacker:

- a password-guessing target;
- a vulnerability surface (for example the 2026 SSH and WebFig issues);
- a path to full router control if authentication is bypassed or credentials are reused.

The strongest control is **not exposing these services to untrusted networks at all**. Use a VPN (WireGuard) and keep management on a trusted segment.

---

## 2. Inventory of management services

```ros
/ip/service/print
```

Expected shape:

```text
Flags: X - DISABLED
Columns: NAME, PORT, ADDRESS, CERTIFICATE
 #   NAME       PORT  ADDRESS           CERTIFICATE
 0   ftp          21
 1   ssh          22  192.0.2.0/24
 2   telnet       23
 3 X www          80
 4   www-ssl     443  192.0.2.0/24      edge-cert
 5   winbox     8291  192.0.2.0/24
 6 X api        8728
 7   api-ssl    8729  192.0.2.0/24      edge-cert
```

Questions:

- Which services are enabled?
- Which have `available-from` restrictions?
- Which are reachable through the WAN interface list (check the firewall, not just the service)?
- Which use TLS, and is the certificate valid?
- Are Telnet and FTP enabled? They are cleartext and should normally be disabled.
- Is `www` (HTTP) enabled while `www-ssl` is also enabled? Prefer HTTPS only.

Important nuance from the manual: `available-from` restricts who is served, but the TCP port still accepts connections. A port scan can still see it open. Firewall rules are the real block.

---

## 3. SSH

### 3.1 Read the settings

```ros
/ip/ssh/print
```

Expected shape:

```text
             strong-crypto: yes
     forwarding-enabled: no
  password-authentication: yes
   host-key-fingerprint: SHA256:...
          host-key-type: ed25519
          host-key-size: 2048
```

Fields that matter:

| Field | Secure target | Why |
|---|---|---|
| `strong-crypto` | `yes` | Disables weak ciphers/MACs/KEX. |
| `forwarding-enabled` | `no` unless needed | Prevents SSH tunneling/pivoting. |
| `password-authentication` | `no` when keys are used | Removes password guessing. `yes-if-no-key` is a transitional compromise. |
| `host-key-type` | `ed25519` where supported | Modern host key. |
| `host-key-fingerprint` | Verified out-of-band | Detects MITM. |

### 3.2 Authentication logs

```ros
/log/print where message~"login failure" and message~"via ssh"
/log/print where message~"logged in" and message~"via ssh"
```

Failed SSH login:

```text
02:11:04 system,error,critical login failure for user admin from 203.0.113.45 via ssh
```

Successful SSH login:

```text
02:31:19 system,info,account user admin logged in from 203.0.113.45 via ssh
```

RouterOS deliberately delays failed SSH logins and accepts up to nine password attempts on one connection before closing it (per the official brute-force guide). Rate limiting is still needed; the delay is not a lockout.

### 3.3 Hardening recommendations

1. Disable SSH on WAN; use a VPN.
2. Restrict with firewall and `available-from`.
3. Import per-administrator public keys; disable password auth once enrollment is complete.
4. Set `strong-crypto=yes`.
5. Set `forwarding-enabled=no` unless there is a documented need.
6. Remove unused users and shared accounts.
7. Log to a remote syslog/SIEM.
8. Consider a non-default port only as noise reduction, not as a security control.
9. Alert on success after repeated failures.

Commands above are examples for the router owner. This skill must not apply them.

---

## 4. WinBox

### 4.1 Exposure

WinBox uses TCP 8291. It is a proprietary management protocol with a long history of client and server vulnerabilities. Modern WinBox v4 is a native cross-platform client; legacy v3 runs under Wine on Linux/macOS.

```ros
/ip/service/print where name=winbox
/ip/firewall/filter/print where chain=input
```

Checks:

- Is `winbox` enabled?
- Is it reachable from WAN?
- Is `available-from` restricted?
- Are there firewall rules that allow 8291 from any source?
- Are there dst-nat rules exposing 8291?

### 4.2 Logs

```ros
/log/print where message~"via winbox"
```

```text
09:14:02 system,error,critical login failure for user admin from 198.51.100.23 via winbox
09:16:10 system,info,account user admin logged in from 198.51.100.23 via winbox
```

A failed-then-successful WinBox sequence from an unexpected source is a high-priority signal.

### 4.3 Hardening

- Close WinBox on WAN. Use a VPN.
- Restrict to a management VLAN and specific source addresses.
- Use strong unique credentials; avoid the default `admin` name.
- Keep WinBox client and RouterOS updated.
- Prefer WinBox v4 where supported.
- Monitor login and configuration-change logs.

---

## 5. API and REST

### 5.1 Exposure

```ros
/ip/service/print where name~"api"
```

- `api` (8728) is cleartext. Never expose it to an untrusted network.
- `api-ssl` (8729) is TLS but requires a certificate for a usable handshake.
- REST is available through the web server on v7 (`/rest`), usually via `www-ssl` (443).

### 5.2 Least privilege

Use a dedicated read-only group:

```ros
/user/group/add name=security-audit policy=read,api,rest-api,ssh,winbox,web
/user/add name=sec-auditor group=security-audit password="<strong>" address=192.0.2.0/24
```

Do not use `full` or the built-in `read` group for automated audits. The built-in `read` group still includes `reboot` and `sensitive`.

### 5.3 Logs

API/REST logins appear with `via api` or `via web`:

```text
11:02:44 system,error,critical login failure for user auditor from 192.0.2.77 via api
11:03:12 system,info,account user auditor logged in from 192.0.2.77 via api
```

### 5.4 Hardening

- Disable `api` if unused; use `api-ssl` only from trusted sources.
- Restrict REST to HTTPS; disable `www`.
- Use a valid certificate and verify it from clients.
- Use a read-only account and an allowlisted proxy.
- Rate-limit and log API calls.
- Rotate credentials and review active sessions.

See `references/routeros-api.md` and `references/read-only-safety.md`.

---

## 6. WebFig and the web server

```ros
/ip/service/print where name~"www"
/ip/service/webserver/print
```

Checks:

- Is HTTP (80) enabled? Cleartext WebFig/REST is a credential risk.
- Is HTTPS (443) enabled with a valid certificate?
- Is the web server reachable from WAN?
- Are graphs, REST, or other endpoints exposed unintentionally?
- Is the RouterOS version affected by a WebFig CVE (for example CVE-2026-84411 or CVE-2026-67281)?

Hardening:

- Disable `www`, keep `www-ssl` only if needed.
- Use a trusted certificate, not the default self-signed one, for exposed management.
- Restrict by firewall and `available-from`.
- Put WebFig behind a VPN.
- Keep RouterOS patched.

---

## 7. Telnet, FTP, MAC-Telnet, MAC-WinBox, RoMON, SNMP

### 7.1 Telnet and FTP

Both are cleartext. Disable unless there is a documented legacy requirement. FTP also has a long vulnerability history on RouterOS.

```ros
/ip/service/print where name~"telnet|ftp"
```

### 7.2 MAC server

MAC-Telnet, MAC-WinBox, and MAC-ping work at Layer 2 and are **not stopped by the IP firewall**.

```ros
/tool/mac-server/print
/tool/mac-server/mac-winbox/print
/tool/mac-server/ping/print
```

Expected shape:

```text
  allowed-interface-list: LAN
```

Hardening:

- Set `allowed-interface-list=none` where MAC management is not needed.
- Never put the WAN interface in the allowed list.
- Remember that a bridge in the list allows connections through its ports.

### 7.3 RoMON

```ros
/tool/romon/print
```

RoMON is a Layer-2 management overlay. If enabled, it can bypass IP firewall expectations. Disable it or protect it with secrets and a trusted segment.

### 7.4 SNMP

```ros
/snmp/print
/snmp/community/print
```

- SNMP is off by default.
- When enabled, the community defines read/write access and source restrictions.
- `public`/`private` communities are weak. Prefer SNMPv3 with authentication and privacy.
- SNMPv1/v2c are cleartext.
- CVE-2026-88464 affects SNMP in RouterOS 7.20+ until fixed; if SNMP is not needed, disable it.

---

## 8. Discovery and cloud services

```ros
/ip/neighbor/discovery-settings/print
/ip/cloud/print
```

- Neighbor discovery (MNDP/CDP/LLDP) leaks identity, version, and topology. Restrict it to LAN.
- MikroTik Cloud DDNS can publish a DNS name for the router. Confirm whether that is intended.
- Back To Home creates a WireGuard VPN and dynamic firewall/NAT rules. Review it as a remote-access path.
- CMR/TR-069, if present, is another management channel. Treat it as part of the management plane.

Hardening:

- `discover-interface-list=none` or LAN-only.
- Disable cloud DDNS if not needed.
- Review Back To Home peers and firewall rules.
- Disable unused management channels.

---

## 9. Evidence of abuse

Look for:

- A service newly enabled or moved to a WAN-reachable port.
- A new user, group, or SSH key.
- A login from an unexpected source or at an unusual time.
- Failure bursts followed by success.
- A management session active during a configuration change.
- New scripts, schedulers, or firewall rules created by that user.
- `/system/history` entries that do not match a change ticket (v7).
- A flagged device-mode status after a compromise check.

Correlation commands:

```ros
/log/print where topics~"account"
/log/print where topics~"system" and message~" by "
/user/active/print
/system/history/print
/system/script/print
/system/scheduler/print
```

A login alone is not compromise. A login plus unexplained configuration changes is.

---

## 10. Version notes

- SSH settings such as `password-authentication` and `strong-crypto` exist in modern v6 and v7; old v6 may lack some options.
- WinBox v4 is the current native client; v3 is legacy.
- REST requires v7.
- `rest-api` is a v7 user policy.
- SNMP CVE-2026-88464 affects v7.20+ until 7.24/7.23.3.
- WebFig CVE-2026-84411 affects <7.24 (and v6 before 6.49.23).
- SSH CVE-2026-67279 and related issues affect versions before 7.24.2/7.23.4/6.49.21.
- Always verify the exact advisory and fixed version before declaring a device vulnerable.

---

## 11. Detection limitations

- Service exposure can be inferred from configuration, but actual internet reachability requires external verification (which this skill must not perform by scanning).
- Logs may not record every failed connection, especially at high volume.
- NAT and port forwarding can expose a service without a matching `available-from` change.
- `available-from` does not close the TCP port.
- MAC-Telnet and RoMON bypass IP firewall.
- A compromised credential produces a legitimate-looking login.
- Log rotation and memory limits can erase the evidence.

---

## 12. Sources

- Services: <https://manual.mikrotik.com/docs/system-information-and-utilities/services>
- SSH: <https://manual.mikrotik.com/docs/management-tools/ssh>
- SSH CLI reference: <https://manual.mikrotik.com/docs/cli-reference/ip/ssh>
- WinBox: <https://manual.mikrotik.com/docs/management-tools/winbox>
- WinBox v3 legacy: <https://manual.mikrotik.com/docs/management-tools/winbox-legacy>
- API: <https://manual.mikrotik.com/docs/developer-guides/api>
- MAC server: <https://manual.mikrotik.com/docs/management-tools/mac-server>
- RoMON: <https://manual.mikrotik.com/docs/management-tools/romon>
- SNMP: <https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/snmp>
- Cloud: <https://manual.mikrotik.com/docs/network-management/cloud>
- Securing your router: <https://manual.mikrotik.com/docs/getting-started/securing-your-router>
- MikroTik security announcements: <https://mikrotik.com/supportsec>
