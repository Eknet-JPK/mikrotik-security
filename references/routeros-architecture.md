# RouterOS Architecture and Version Differences

**Scope:** RouterOS platform model, packages, interfaces, services, and the v6/v7 differences that change security analysis.
**Last reviewed:** 2026-11-11
**Primary source:** MikroTik RouterOS 7.26 manual (<https://manual.mikrotik.com/>), with v6 compatibility notes where behavior differs.

---

## 1. What RouterOS is

RouterOS is MikroTik's network operating system for RouterBOARD hardware, x86 systems, and Cloud Hosted Router (CHR). It combines routing, bridging, firewalling, NAT, VPN, wireless control, hotspot, PPP, queues, monitoring, and automation in one configuration database.

For security work, treat the router as three planes:

| Plane | Examples | Why it matters |
|---|---|---|
| **Management plane** | WinBox, SSH, WebFig, API, REST, MAC-Telnet, RoMON, SNMP | Compromise here means full control of the device. |
| **Control plane** | Routing protocols, ARP, DHCP, DNS, NDP, VRRP, wireless authentication | Manipulation redirects or denies traffic without touching endpoints. |
| **Data plane** | Filter, RAW, NAT, mangle, FastTrack, queues, bridges, VPN | Determines what traffic is allowed, translated, logged, or bypassed. |

Most serious RouterOS incidents start with management-plane exposure (WinBox/SSH/API/WebFig reachable from the internet), weak credentials, or an unpatched web/SSH service. Firewall review alone is not enough.

---

## 2. Core identity and health commands

### 2.1 System resource

```ros
/system/resource/print
```

Expected shape (synthetic example):

```text
uptime: 21d4h32m10s
version: 7.16.2 (stable)
build-time: 2026-02-10 09:12:44
factory-software: 7.11
free-memory: 812.4MiB
total-memory: 1024.0MiB
cpu: ARM64
cpu-count: 4
cpu-frequency: 1400MHz
cpu-load: 7%
free-hdd-space: 812.0MiB
total-hdd-space: 1024.0MiB
architecture-name: arm64
board-name: RB5009UG+S+
platform: MikroTik
```

Interpretation:

- `version` is the RouterOS release. Compare it with the advisory fixed versions in `references/vulnerability-assessment.md`.
- `architecture-name` and `board-name` matter for package compatibility and firmware.
- `factory-software` is the version installed at manufacture, not the current version.
- High `cpu-load` with no known workload is an indicator, not proof, of flood or crypto-mining activity.
- Low `free-memory` can cause conntrack allocation failures and `invalid` packets.

### 2.2 Identity, board, clock, packages

```ros
/system/identity/print
/system/routerboard/print
/system/clock/print
/system/ntp/client/print
/system/package/print
```

Expected shape:

```text
[admin@edge-rtr] > /system/routerboard/print
       routerboard: yes
             model: RB5009UG+S+
     serial-number: HEQ08XXXXXX
     firmware-type: arm64
  factory-firmware: 7.11
  current-firmware: 7.13
  upgrade-firmware: 7.13
```

```text
[admin@edge-rtr] > /system/clock/print
                  time: 14:22:51
                  date: 2026-11-11
         time-zone-name: Asia/Bangkok
             gmt-offset: +07:00
```

Interpretation:

- `current-firmware` vs `upgrade-firmware`: RouterBOOT firmware is separate from RouterOS. A mismatch is a maintenance issue, not automatically a vulnerability.
- A wrong clock or time zone breaks log correlation. Check NTP synchronization before building a timeline.
- `factory-firmware` does not indicate the running version.
- On CHR/x86, `/system/routerboard/print` may be absent; use `/system/resource/print` and `/system/license/print`.

### 2.3 Device mode and history (v7)

```ros
/system/device-mode/print
/system/history/print
```

- `/system/device-mode/print` shows restrictions and, on recent v7, whether the router is in a **flagged** state after a compromise check. A critical log entry about a flagged device is a high-confidence indicator; follow MikroTik's flagged-status guidance.
- `/system/history/print` shows recent configuration actions and the user who performed them. It is a v7 feature and is not a complete audit log; it can be limited or cleared by an administrator.

---

## 3. Packages, licensing, and attack surface

RouterOS functionality is grouped into packages. The main `routeros` bundle covers routing, firewall, NAT, PPP, hotspot, DHCP, DNS, and basic wireless drivers. Optional packages add features and attack surface.

Typical optional capabilities:

| Capability | Package / menu | Security relevance |
|---|---|---|
| Containers | `container` package, `/container` | Image imports, mounts, network namespace, supply chain. |
| The Dude | `dude` | Network monitoring; historically discontinued. |
| User Manager | `user-manager` | RADIUS/AAA, credential store. |
| SMB | `/ip/smb` | File sharing, authentication surface. |
| Web proxy | `/ip/proxy` | Caching proxy, possible abuse. |
| SOCKS | `/ip/socks` | Proxy abuse, pivot. |
| SNMP | `/snmp` | Information disclosure, write access if misconfigured. |
| Hotspot | `/ip/hotspot` | User authentication, captive portal, walled garden. |
| Wireless | `wireless` or `wifi-qcom` | Radio authentication, rogue AP, WPS. |

```ros
/system/package/print
```

Interpretation:

- An installed package with no business purpose is unnecessary attack surface. Recommend removal only through a change process; never remove it in read-only mode.
- Package version should match RouterOS version. A mismatched package can fail or behave unexpectedly.
- `disabled` packages still occupy storage but are not active.

Licensing:

- RouterBOARD hardware ships with a license level that limits features such as tunnel count and user sessions.
- CHR uses Free/P1/P10/P-Unlimited licenses and requires periodic revalidation for paid tiers.
- License level is not a security control. A low license level does not make a router safe, and a high level does not make it unsafe.

---

## 4. Interface, bridge, and VLAN model

### 4.1 Interfaces

```ros
/interface/print
/interface/ethernet/print
/ip/address/print
```

Expected shape:

```text
Flags: R - RUNNING; S - SLAVE
Columns: NAME, TYPE, ACTUAL-MTU, L2MTU, MAC-ADDRESS
#   NAME      TYPE      ACTUAL-MTU  L2MTU  MAC-ADDRESS
0 R ether1    ether             1500   1514  00:00:5E:00:53:01
1 R ether2    ether             1500   1514  00:00:5E:00:53:02
2 R bridge    bridge            1500   1514  00:00:5E:00:53:AA
```

Interpretation:

- `R` means running (link up), not "routed".
- An interface with no IP address can still carry bridged or VLAN traffic.
- `L2MTU` below the expected value can break VLANs or PPPoE; it is not a security finding by itself.

### 4.2 Bridges and VLANs

```ros
/interface/bridge/print
/interface/bridge/port/print
/interface/bridge/vlan/print
/interface/vlan/print
```

Key security point: **bridged traffic does not automatically traverse the IP firewall input/forward chains.** If two segments are bridged together, the router may switch frames at Layer 2 without applying IP filter rules. Segmentation requires either:

- no bridge between the segments (route instead), or
- bridge VLAN filtering with a correct VLAN table and PVIDs, or
- bridge firewall rules (where supported) for Layer-2 control.

`/interface/bridge/vlan/print` shows the VLAN table when `vlan-filtering=yes`. An empty or inconsistent table with `vlan-filtering=yes` can black-hole traffic or leak VLANs, depending on the port configuration.

Version notes:

- Bridge VLAN filtering is available in v6.41+ and v7.
- Very old v6 bridges (pre-6.41) use a different model and no VLAN filtering.
- `master-port` was removed in v6.41+; do not use it in advice for modern v6/v7.

### 4.3 Interface lists

```ros
/interface/list/print
/interface/list/member/print
```

Interface lists are the backbone of maintainable firewall rules. A WAN interface that is not in the WAN list will not be protected by rules that match `in-interface-list=WAN`. Always verify membership before concluding that a firewall rule protects an interface.

---

## 5. Routing, ARP, DHCP, DNS

### 5.1 Routing

```ros
/ip/route/print
/ipv6/route/print
```

Expected shape:

```text
Flags: D - DYNAMIC; A - ACTIVE; C - CONNECT, S - STATIC
Columns: DST-ADDRESS, GATEWAY, DISTANCE
#       DST-ADDRESS        GATEWAY         DISTANCE
0 ADS   0.0.0.0/0          203.0.113.1            1
1 ADC   192.168.88.0/24    bridge                 0
```

Interpretation:

- An unexpected default route is a critical redirect risk. Correlate with `/system/history` and log entries.
- Multiple default routes with different distances are normal in failover designs.
- Policy routing in v7 uses `/routing/rule` and `/routing/table`; v6 uses `/ip/route/rule` and `/ip/route` tables. Verify the version before advising.

### 5.2 ARP

```ros
/ip/arp/print
/ip/settings/print
```

Expected shape:

```text
Flags: D - DYNAMIC; C - COMPLETE
Columns: ADDRESS, MAC-ADDRESS, INTERFACE
#   ADDRESS         MAC-ADDRESS        INTERFACE
0 DC 192.168.88.10   00:00:5E:00:53:10  bridge
1 DC 192.168.88.11   00:00:5E:00:53:11  bridge
```

Interpretation:

- One MAC address claiming many IPs, or a MAC changing for a fixed IP, is suspicious — but can be legitimate (VRRP, failover, NIC replacement).
- RouterOS alone cannot confirm ARP spoofing. Corroborate with switch DHCP snooping/DAI, wireless logs, or an IDS.
- `arp=reply-only` on an interface requires static ARP entries for hosts; it can break dynamic clients.
- `rp-filter=strict` reduces IP spoofing but breaks asymmetric routing. `loose` is a compromise.

### 5.3 DHCP

```ros
/ip/dhcp-server/print
/ip/dhcp-server/network/print
/ip/dhcp-server/lease/print
/ip/dhcp-client/print
```

Interpretation:

- A second DHCP server on the segment (rogue DHCP) can hand out a malicious gateway/DNS. RouterOS does not reliably detect this by itself. Look for clients with unexpected gateways, duplicate offers in external captures, or switch DHCP-snooping alerts.
- Lease churn (many new leases in a short time) can indicate a starvation attack or a legitimate bring-your-own-device event.
- A DHCP client on a WAN interface is normal; a DHCP server on the WAN interface is a serious misconfiguration.

### 5.4 DNS

```ros
/ip/dns/print
/ip/dns/static/print
/ip/dns/cache/print
```

Expected shape:

```text
servers: 203.0.113.53
dynamic-servers:
use-doh-server:
verify-doh-cert: no
allow-remote-requests: yes
cache-size: 2048KiB
cache-used: 312KiB
```

Interpretation:

- `allow-remote-requests=yes` makes the router a DNS server for any client that can reach port 53. Without firewall rules, it can become an open resolver used in DNS amplification.
- Unexpected static entries can redirect names (a common persistence technique). Compare against a known-good baseline.
- DoH (`use-doh-server`) may bypass local DNS logging and policy. It is a privacy feature but a visibility gap.
- The DNS cache is a snapshot. It is not a query log.

---

## 6. PPP, hotspot, wireless, and queues

### 6.1 PPP and VPN

```ros
/ppp/secret/print
/ppp/active/print
/ppp/profile/print
/interface/pppoe-server/server/print
```

Security relevance:

- PPP secrets are credentials. Use `.proplist` to avoid passwords.
- An unexpected active session can indicate credential abuse.
- PPTP is cryptographically obsolete; prefer WireGuard, IPsec, or SSTP/OpenVPN with modern TLS. Do not recommend PPTP for new deployments.
- L2TP without IPsec is unencrypted. Verify the actual configuration, not just the menu name.

### 6.2 Hotspot

```ros
/ip/hotspot/print
/ip/hotspot/profile/print
/ip/hotspot/user/print
/ip/hotspot/active/print
```

Security relevance:

- Hotspot is an authentication surface. Weak local users, shared vouchers, or a permissive walled garden can be abused.
- A hotspot on an interface that also serves management traffic can expose the router.
- Active sessions show who is online; they are not proof of identity.

### 6.3 Wireless

```ros
/interface/wireless/print
/interface/wireless/security-profiles/print
```

```ros
/interface/wifi/print
/interface/wifi/security/print
```

Version notes:

- Legacy 802.11 a/b/g/n devices use `/interface/wireless` (wireless package).
- Wi-Fi 6/7 devices may use `/interface/wifi` with `wifi-qcom` or `wifi-qcom-ac`.
- Some devices support both drivers. Confirm the installed package and the active menu before giving commands.

Security relevance:

- WPA2-PSK with a weak or shared passphrase is a credential risk.
- WPA3/OWE improves protection where supported.
- WPS should be disabled unless specifically required.
- A rogue AP with the same SSID is a Layer-2 attack that RouterOS alone cannot detect.
- Wireless registration tables show associated clients; use them for inventory, not for proof of compromise.

### 6.4 Queues

```ros
/queue/simple/print
/queue/tree/print
/queue/type/print
```

Queues shape traffic. They are not a security control, but they can obscure traffic analysis and be abused for resource exhaustion. FastTracked traffic bypasses simple queues; do not assume a queue applies to all forwarded packets.

---

## 7. Services and management plane

```ros
/ip/service/print
```

Default ports:

| Service | Port | Notes |
|---|---|---|
| FTP | 21 | Cleartext; disable unless required. |
| SSH | 22 | Encrypts; still exposed to brute force. |
| Telnet | 23 | Cleartext; disable. |
| HTTP (www) | 80 | WebFig/REST; cleartext; disable or restrict. |
| HTTPS (www-ssl) | 443 | Requires a certificate for proper TLS. |
| WinBox | 8291 | Proprietary management protocol. |
| API | 8728 | Cleartext; restrict or disable. |
| API-SSL | 8729 | TLS; requires a certificate. |
| Reverse proxy | 443 | Dynamic listener when configured. |

MAC-Telnet, MAC-WinBox, and MAC-ping are Layer-2 services. IP firewall rules do not stop them; restrict them with `/tool/mac-server` settings.

---

## 8. RouterOS v6 vs v7

| Area | RouterOS v6 | RouterOS v7 |
|---|---|---|
| Status | Legacy; 6.49.x still receives security fixes | Current major version |
| Kernel | Older Linux kernel | New kernel; new performance characteristics |
| CLI | Classic CLI | New CLI style; most v6 commands still accepted |
| Routing | Legacy routing/BGP/OSPF | Redesigned routing stack, `/routing/...`, new BGP/OSPF |
| REST API | Not available | Available (`/rest`, `www-ssl`) |
| WireGuard | Not available | Available |
| Containers | Not available | Available with the container package |
| `/system/history` | Not available | Available |
| Bridge VLAN filtering | 6.41+ | Available |
| RAW firewall | 6.36+ | Available |
| Wireless | Legacy `/interface/wireless` | Legacy plus `/interface/wifi` for Wi-Fi 6/7 packages |
| Logging | Classic topics and format | Adds CEF (7.18+), `with-extra-info`, extra fields |
| User policies | Version-dependent | Includes `rest-api`; verify `sensitive` behavior |
| API | Yes (8728/8729) | Yes (8728/8729) |
| SNMP | Yes | Yes; v7.20+ has CVE-2026-88464 exposure until fixed |

Practical rules:

1. Ask or read the version before giving a command.
2. If a menu is absent, do not tell the user to "just enable it" in read-only mode. Explain the version difference.
3. Do not apply v7 routing examples to v6.
4. Do not assume REST exists on v6.
5. Do not assume `with-extra-info` exists on older v6. Fall back to parsing the message text.
6. v6 is not automatically vulnerable because it is old. Verify the specific CVE and fixed version.

---

## 9. Security implications of architecture

- **Bridging bypasses IP firewall.** Design segmentation deliberately.
- **FastTrack bypasses filter, mangle, queues, and connection tracking for established flows.** A rule added after FastTrack may not affect existing connections.
- **NAT hides sources.** Internal attack sources may appear as the router's public address in external logs.
- **Management services are the crown jewels.** Exposed WinBox/SSH/API/WebFig is a higher risk than almost any other finding.
- **User policies are coarse.** The built-in `read` group can reboot and see sensitive data. Use a custom group.
- **Optional packages increase attack surface.** Remove what is not needed.
- **RouterOS is a general-purpose Linux system underneath.** A compromised router can run scripts, proxy traffic, and persist across reboots.
- **A router compromise affects every host behind it.** Impact assessment must include traffic interception, DNS manipulation, and lateral movement.

---

## 10. Detection limitations

- `/system/resource/print` is a snapshot; CPU spikes may be missed.
- `/system/history` is not a full audit trail and can be cleared.
- Bridge and switch-chip forwarding may not be visible in IP counters.
- FastTracked flows may not increment filter counters as expected.
- Package lists do not prove a package is actively used.
- Interface counters can wrap or reset; record the sampling window.
- RouterBOOT firmware state does not prove RouterOS patch level; check both.

---

## 11. Sources

- RouterOS manual, introduction and structure: <https://manual.mikrotik.com/docs/introduction>
- System resource: <https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/resource>
- RouterBOARD: <https://manual.mikrotik.com/docs/hardware/routerboard>
- Packages: <https://manual.mikrotik.com/docs/getting-started/installation-and-upgrade/packages>
- Services: <https://manual.mikrotik.com/docs/system-information-and-utilities/services>
- Bridging and switching: <https://manual.mikrotik.com/docs/bridging-and-switching>
- VLAN: <https://manual.mikrotik.com/docs/bridging-and-switching/vlan>
- DNS: <https://manual.mikrotik.com/docs/network-management/dns>
- Connection tracking: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/connection-tracking>
- User policies: <https://manual.mikrotik.com/docs/authentication-authorization-accounting/user>
- Upgrading to v7: <https://manual.mikrotik.com/docs/getting-started/upgrading-to-v7>
- Securing your router: <https://manual.mikrotik.com/docs/getting-started/securing-your-router>
