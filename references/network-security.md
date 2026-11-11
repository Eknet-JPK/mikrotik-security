# Network Security Fundamentals for RouterOS Analysts

**Scope:** The protocol and design knowledge needed to interpret RouterOS evidence correctly.
**Last reviewed:** 2026-11-11
**Applies to:** RouterOS v6 and v7; protocol behavior is version-independent unless noted.

---

## 1. TCP, UDP, and ICMP

### 1.1 TCP

TCP provides reliable, ordered, connection-oriented delivery using a three-way handshake:

```text
Client                          Server
  | -------- SYN (seq=x) --------> |
  | <--- SYN+ACK (seq=y, ack=x+1) - |
  | -------- ACK (ack=y+1) -------> |
  | ========= data =============== |
  | -------- FIN/ACK -------------> |
```

Flags used in analysis:

| Flag | Meaning | Security relevance |
|---|---|---|
| SYN | Start a connection | SYN scans, SYN floods, new-connection counters |
| ACK | Acknowledge data | ACK scans, stateless firewall evasion |
| FIN | Close | FIN scans, stealthy scanning |
| RST | Reset | Closed-port responses, scan detection |
| PSH | Push data | Usually application behavior |
| URG | Urgent pointer | Rare; can be abused for evasion |
| ECE/CWR | Congestion notification | Rare in attack analysis |

RouterOS exposes TCP state in connection tracking:

```ros
/ip/firewall/connection/print where protocol=tcp
```

Expected fields include `tcp-state` (`syn-sent`, `syn-recv`, `established`, `fin-wait`, `time-wait`, `close`, and others), `orig-packets`, `repl-packets`, `timeout`.

Interpretation:

- Many `syn-sent` entries with no replies can indicate a SYN scan or a SYN flood, but also a broken upstream or a busy NAT gateway.
- A completed handshake followed by a reset is normal for closed services.
- A half-open connection is not proof of malicious intent.

### 1.2 UDP

UDP is connectionless. RouterOS still tracks UDP "connections" for NAT and stateful filtering, using a timeout.

Security relevance:

- UDP is easy to spoof, which enables amplification/reflection (DNS, NTP, SSDP, memcached, CLDAP).
- A flood of small UDP packets can exhaust conntrack and CPU.
- DNS over UDP 53 is the most common amplification vector.
- Legitimate UDP flows include DNS, DHCP, NTP, QUIC/HTTP3, VoIP, and VPNs.

Commands:

```ros
/ip/firewall/connection/print where protocol=udp
```

Limitations:

- A UDP "connection" is inferred; there is no handshake to prove the source.
- Spoofed UDP sources are common in attacks, so source addresses are weak evidence.

### 1.3 ICMP

ICMP is used for diagnostics and error reporting. Common types:

| Type | Name | Notes |
|---|---|---|
| 0 | Echo reply | Ping response |
| 3 | Destination unreachable | Codes 0/1/3/4/9/10/13 |
| 5 | Redirect | Can redirect a host's gateway; usually blocked on routers |
| 8 | Echo request | Ping |
| 11 | Time exceeded | Traceroute |
| 12 | Parameter problem | Malformed packets |

Security relevance:

- ICMP floods are volumetric and simple.
- ICMP tunneling can exfiltrate data through echo payloads. RouterOS firewall rules can block or rate-limit, but payload inspection is not native.
- ICMP redirects should not be accepted on a router (`accept-redirects=no` is the secure default on routers).
- Blocking all ICMP breaks Path MTU Discovery and IPv6. Permit essential types.

Commands:

```ros
/ip/settings/print
/ip/firewall/filter/print where protocol=icmp
```

---

## 2. DNS security

### 2.1 How RouterOS DNS is used

- As a **resolver** for the router itself and, if `allow-remote-requests=yes`, for clients.
- As an **authoritative-like local resolver** through `/ip/dns/static` entries.
- With **DoH** through `use-doh-server` (v7; verify version).
- With **adlists** for blocking (v7).

### 2.2 Risks

| Risk | Mechanism | RouterOS visibility |
|---|---|---|
| Open resolver | `allow-remote-requests=yes` + port 53 reachable from WAN | Configuration + firewall rules |
| DNS amplification | Spoofed queries to an open resolver, large responses to victim | Interface/conntrack counters; not query content |
| Cache poisoning | Malicious/forged responses | Very limited; static entries are visible |
| DNS tunneling | Encoded data in queries/responses | Not visible without payload capture |
| DoH bypass | Encrypted DNS to an external resolver | Only destination IP/port and volume |
| Static record hijack | Unauthorized `/ip/dns/static` entry | Configuration + `/system/history` |
| DDoS via DNS | Flood of queries to the router | Conntrack, CPU, interface stats |

### 2.3 Checks

```ros
/ip/dns/print
/ip/dns/static/print
/ip/firewall/filter/print where dst-port=53
/ipv6/firewall/filter/print where dst-port=53
```

Expected shape (synthetic):

```text
[admin@edge-rtr] > /ip/dns/print
          servers: 203.0.113.53
  dynamic-servers:
    use-doh-server:
   verify-doh-cert: no
allow-remote-requests: yes
        cache-size: 4096KiB
         cache-used: 812KiB
```

Interpretation: `allow-remote-requests=yes` means the router answers DNS on port 53. Whether that is an open resolver depends on the firewall rules, not on this setting alone.

Look for:

- `allow-remote-requests=yes` with no firewall restriction.
- Static entries pointing to unexpected addresses.
- A forwarder or DoH server that bypasses local policy.
- Firewall rules accepting UDP/TCP 53 from WAN.
- DNS cache size too small for the configured adlists (operational, not security).

### 2.4 Defensive guidance

- Restrict port 53 to LAN clients; block it from WAN.
- Keep the resolver disabled if another device provides DNS.
- Review static entries against a baseline.
- Log DNS configuration changes, not every query.
- Do not claim DNS tunneling from volume alone; it needs payload or threat-intel correlation.

---

## 3. ARP security

ARP maps IPv4 addresses to MAC addresses on a Layer-2 segment. It has no authentication.

### 3.1 Attacks

- **ARP spoofing/poisoning** — attacker claims an IP (often the gateway) with its own MAC, enabling MITM or DoS.
- **Gratuitous ARP** — unsolicited updates; can be legitimate (failover) or malicious.
- **ARP flooding** — fills the ARP table, causing instability.
- **Proxy ARP abuse** — a router answers for addresses it does not own.

### 3.2 RouterOS evidence

```ros
/ip/arp/print
/ip/settings/print
```

Expected shape (synthetic):

```text
[admin@edge-rtr] > /ip/arp/print
Flags: D - DYNAMIC; C - COMPLETE
Columns: ADDRESS, MAC-ADDRESS, INTERFACE
 #   ADDRESS         MAC-ADDRESS        INTERFACE
 0 DC 192.168.88.10   00:00:5E:00:53:10  bridge
 1 DC 192.168.88.11   00:00:5E:00:53:11  bridge
```

Interpretation:

- Two entries for one IP, or a gateway MAC that changes, is suspicious.
- A single MAC for many IPs can be a router, VRRP, or a proxy ARP device.
- Dynamic ARP entries are normal.
- `arp=reply-only` on an interface means the router only answers for static entries; it is a hardening option, not a detection tool.
- RouterOS cannot see ARP on a switched segment unless the traffic reaches the router or the switch reports it.

### 3.3 Defensive guidance

- Use switch features: DHCP snooping, Dynamic ARP Inspection, port security.
- Segment trust boundaries with VLANs.
- Use static ARP only where operationally practical.
- Monitor gateway MAC changes from an external sensor.
- Do not claim ARP spoofing from RouterOS ARP data alone.

---

## 4. VLAN and segmentation security

### 4.1 VLAN basics

An 802.1Q tag carries a VLAN ID (1–4094). A trunk carries multiple VLANs; an access port carries one untagged VLAN.

RouterOS:

```ros
/interface/vlan/print
/interface/bridge/vlan/print
/interface/bridge/port/print
```

### 4.2 Risks

| Risk | Cause | Evidence |
|---|---|---|
| VLAN hopping | Trunk reachable from an access port, double tagging, native VLAN mismatch | Bridge VLAN table, port PVIDs, switch config |
| Flat network | All devices in one VLAN | `/ip/address`, bridge ports |
| Management VLAN shared with users | Management plane exposed to clients | Interface/VLAN design |
| Guest network bridged to LAN | Segmentation failure | Bridge ports/VLAN table |
| Unfiltered inter-VLAN routing | Router routes between VLANs without firewall rules | Forward chain rules |

### 4.3 Checks

- Is `vlan-filtering=yes` on the bridge?
- Does every port have the correct `pvid` and tagged/untagged membership?
- Is the management VLAN reachable from guest/IoT VLANs?
- Are inter-VLAN flows filtered in `forward`, or only bridged?
- Is IPv6 segmentation consistent with IPv4?

RouterOS alone cannot prove VLAN hopping; it can show a permissive configuration.

---

## 5. NAT security

NAT translates addresses; it is **not** a firewall.

- `srcnat`/masquerade hides internal sources. It does not prevent outbound attacks.
- `dstnat` exposes internal services. It does not automatically allow them; the forward chain still applies for new connections.
- NAT hides the original source from external logs.
- Hairpin NAT changes the apparent source and can confuse analysis.
- UPnP/NAT-PMP can create dynamic mappings without administrator review.

Commands:

```ros
/ip/firewall/nat/print
/ip/firewall/nat/print stats
/ip/upnp/print
/ip/firewall/connection/print where dstnat=yes
```

Findings:

- A dst-nat to an internal management interface is high risk.
- A dst-nat with no source restriction is internet-exposed.
- A masquerade rule not scoped to WAN can hide traffic unexpectedly.
- Disabled dst-nat rules are not exposure today, but indicate drift.

---

## 6. Remote access and VPN security

### 6.1 Management access options

| Method | Encryption | Recommendation |
|---|---|---|
| WinBox | Proprietary; modern WinBox supports TLS | Restrict to LAN/VPN; never expose to WAN. |
| SSH | Yes | Keys preferred; restrict source; disable password auth where possible. |
| WebFig (HTTPS) | TLS | Valid certificate; restrict source. |
| API-SSL | TLS | Read-only account; restrict source. |
| Telnet/FTP/HTTP | None | Disable. |
| MAC-Telnet/MAC-WinBox | Layer 2, no IP firewall | Restrict with `/tool/mac-server`. |
| RoMON | Layer 2 overlay | Disable or secure with secrets. |
| SNMP v1/v2c | Community string | Avoid; use SNMPv3 or disable. |

### 6.2 VPN options

| VPN | Status | Notes |
|---|---|---|
| WireGuard | v7 | Modern, simple, UDP; manage keys carefully. |
| IPsec (IKEv2) | v6/v7 | Strong when configured correctly; verify proposals. |
| SSTP | v6/v7 | TLS-based; certificate-dependent. |
| OpenVPN | v6/v7 | TLS; verify certificate and cipher settings. |
| L2TP/IPsec | v6/v7 | Acceptable with IPsec; L2TP alone is unencrypted. |
| PPTP | Legacy | Cryptographically broken; do not recommend. |

Checks:

```ros
/interface/wireguard/print
/interface/wireguard/peers/print
/ip/ipsec/peer/print
/ip/ipsec/policy/print
/ppp/secret/print
/ppp/active/print
```

Interpretation:

- An unexpected active VPN peer can indicate credential compromise.
- A WireGuard peer with `0.0.0.0/0` allowed-ips routes all traffic through the tunnel; verify intent.
- A PPTP/L2TP server exposed to WAN is an authentication and vulnerability surface.
- VPN does not replace endpoint security; a compromised client can attack the internal network.

---

## 7. Management-plane security

The management plane includes every way to change the router:

- WinBox, WebFig, SSH, Telnet, API, REST, MAC-Telnet, MAC-WinBox, RoMON, SNMP (write), TR-069, CMR, cloud services.
- Local console, LCD, and reset button (physical).
- Scripts, schedulers, and containers (logical).

Principles:

1. **Least exposure** — close everything not needed on untrusted networks.
2. **Least privilege** — dedicated accounts and groups, not shared `admin`.
3. **Strong authentication** — long unique passwords, SSH keys, MFA at the VPN layer.
4. **Encrypted transport** — SSH, API-SSL, HTTPS, VPN.
5. **Source restriction** — firewall + `available-from` + user `address`.
6. **Auditability** — remote syslog, accurate clock, config-change logs.
7. **Recoverability** — out-of-band access, documented rollback.

Commands:

```ros
/ip/service/print
/user/print
/user/group/print
/user/active/print
/tool/mac-server/print
/tool/romon/print
/snmp/print
/ip/cloud/print
```

---

## 8. Network access control (NAC)

NAC ensures only authorized devices/users join a segment.

RouterOS capabilities:

- **802.1X** (dot1x) for ports/wireless with a RADIUS server.
- **Hotspot** captive portal for guest/user authentication.
- **PPP/PPPoE** authentication for subscriber networks.
- **Wireless security profiles** (WPA2/WPA3, EAP).
- **RADIUS** integration.
- **Port isolation / bridge filtering** on some hardware.

Limits:

- RouterOS is not a full NAC appliance; it does not inventory endpoints or enforce posture.
- Switch-level port security and DHCP snooping may be required.
- MAC filtering is weak (MAC spoofing is trivial).
- A shared PSK is not per-device identity.

Evidence:

```ros
/interface/dot1x/print
/radius/print
/ip/hotspot/active/print
/ppp/active/print
/interface/wireless/registration-table/print
/interface/wifi/registration-table/print
```

---

## 9. What RouterOS can and cannot detect

| Threat | RouterOS-only visibility | Needs external evidence |
|---|---|---|
| SSH/WinBox/API brute force | Login failure logs, source IPs | Credential success validation, threat intel |
| Port scan | Firewall logs/counters if configured | IDS/flow analysis for stealth scans |
| SYN/UDP/ICMP flood | Interface pps, conntrack, CPU | Upstream/flow data to confirm DDoS |
| DNS amplification | Outbound DNS volume, open resolver config | Packet capture, ISP data |
| ARP spoofing | ARP table anomalies | Switch DAI/DHCP snooping, IDS |
| Rogue DHCP | DHCP logs/leases, client symptoms | Switch DHCP snooping, packet capture |
| MITM | ARP/gateway anomalies, certificate errors | IDS, endpoint, TLS inspection |
| Lateral movement | Forward logs, connection table | NetFlow, IDS, EDR |
| C2 | Outbound connections, volume, destinations | DNS/flow/payload analysis, threat intel |
| Data exfiltration | Outbound volume | Flow/payload analysis, DLP |

Use this table to avoid overclaiming.

---

## 10. Sources

- TCP/IP and networking fundamentals: <https://manual.mikrotik.com/docs/getting-started/networking-fundamentals>
- DNS: <https://manual.mikrotik.com/docs/network-management/dns>
- NAT: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall/nat>
- Connection tracking: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/connection-tracking>
- VLAN: <https://manual.mikrotik.com/docs/bridging-and-switching/vlan>
- WireGuard: <https://manual.mikrotik.com/docs/virtual-private-networks/wireguard>
- IPsec: <https://manual.mikrotik.com/docs/virtual-private-networks/ipsec>
- SSH: <https://manual.mikrotik.com/docs/management-tools/ssh>
- Securing your router: <https://manual.mikrotik.com/docs/getting-started/securing-your-router>
- NIST CSF 2.0: <https://www.nist.gov/cyberframework>
- MITRE ATT&CK: <https://attack.mitre.org/>
