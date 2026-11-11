# Synthetic Attack Pattern Library

> **SYNTHETIC DATA — FOR TRAINING ONLY.**
> Addresses are from RFC 5737 documentation ranges. MAC addresses are from the RFC 7042 documentation range. Users and events are fictional.

Each scenario shows the evidence a RouterOS analyst might see, the reasoning, the classification, and the limits. The goal is to practice **not overclaiming**.

---

## Scenario 1 — SSH brute force followed by success

### Evidence

```text
2026-11-11 02:11:04 system,error,critical login failure for user admin from 203.0.113.45 via ssh
2026-11-11 02:11:06 system,error,critical login failure for user root from 203.0.113.45 via ssh
2026-11-11 02:11:09 system,error,critical login failure for user test from 203.0.113.45 via ssh
...
2026-11-11 02:29:31 system,error,critical login failure for user admin from 203.0.113.45 via ssh
2026-11-11 02:31:19 system,info,account user admin logged in from 203.0.113.45 via ssh
2026-11-11 02:33:02 system,info user svc-backup added by admin
2026-11-11 02:35:44 system,info script added by admin
```

Full synthetic count: 412 failures, 37 usernames, 18 minutes, one source.

### Analysis

- High-rate, multi-username guessing: brute force/spraying.
- Same source succeeds 1m48s after the last failure: failure→success pivot.
- New user and script after the login: possible persistence.

### Classification

- Attempts: **ATTEMPTED ATTACK**, HIGH confidence.
- Login: **UNAUTHORIZED ACCESS (possible)**, HIGH confidence it occurred, MEDIUM that it was unauthorized.
- With owner denial + verified new objects: **CONFIRMED COMPROMISE**, HIGH confidence.

### What would change the conclusion

Owner confirms the login and changes were legitimate (for example, an administrator working through a VPN). Then the failures remain an attempted attack, but there is no compromise.

### Recommendation

Preserve evidence, confirm with the owner, disable the new account if unauthorized, rotate credentials, close SSH on WAN, add remote syslog, alert on failure→success.

**ATT&CK:** T1110, T1078, T1133, T1136.

---

## Scenario 2 — Vertical TCP SYN scan

### Evidence

```text
2026-11-11 03:14:55 firewall,info SCAN-SYN input: in:ether1 out:(none), src-mac 00:00:5E:00:53:92,
    proto TCP, 198.51.100.88:51222->192.0.2.1:22, len 60
2026-11-11 03:14:55 firewall,info SCAN-SYN input: in:ether1 out:(none), src-mac 00:00:5E:00:53:92,
    proto TCP, 198.51.100.88:51223->192.0.2.1:23, len 60
2026-11-11 03:14:56 firewall,info SCAN-SYN input: in:ether1 out:(none), src-mac 00:00:5E:00:53:92,
    proto TCP, 198.51.100.88:51224->192.0.2.1:80, len 60
2026-11-11 03:14:56 firewall,info SCAN-SYN input: in:ether1 out:(none), src-mac 00:00:5E:00:53:92,
    proto TCP, 198.51.100.88:51225->192.0.2.1:443, len 60
2026-11-11 03:14:57 firewall,info SCAN-SYN input: in:ether1 out:(none), src-mac 00:00:5E:00:53:92,
    proto TCP, 198.51.100.88:51226->192.0.2.1:8291, len 60
2026-11-11 03:14:57 firewall,info SCAN-SYN input: in:ether1 out:(none), src-mac 00:00:5E:00:53:92,
    proto TCP, 198.51.100.88:51227->192.0.2.1:8728, len 60
```

### Analysis

- One source to many sequential destination ports on one host: vertical scan.
- The firewall logging rule matched new SYNs; the traffic was dropped by the default input policy.
- No successful login follows in the available window.

### Classification

**ATTEMPTED ATTACK (reconnaissance)**, MEDIUM/HIGH confidence. The scan is clear; intent is inferred.

### What would change the conclusion

The source is an authorized scanner or monitoring host, or the ports are part of a known application's behavior. Verify authorization.

### Recommendation

Keep default-deny, log selectively, rate-limit repeat scanners, add IDS/NetFlow for stealth scans, confirm no service was exposed.

**ATT&CK:** T1046, T1595.

---

## Scenario 3 — SYN flood / connection exhaustion

### Evidence

```text
[admin@edge-rtr] > /interface/monitor-traffic interface=ether1 once
        rx-rate: 840.2Mbps
   rx-packets-per-second: 1,402,000

[admin@edge-rtr] > /ip/firewall/connection/tracking/print
        enabled: auto
      max-entries: 1048576
    total-entries: 1,012,440

[admin@edge-rtr] > /system/resource/print
       cpu-load: 98%
   free-memory: 41.2MiB
```

Firewall stats show the invalid-drop rule rising; the router's SSH service is slow.

### Analysis

- Near-line-rate small packets, conntrack near max, CPU/memory pressure.
- Pattern is consistent with a SYN flood or a high-rate scan.
- RouterOS cannot prove distribution or intent from these counters alone.

### Classification

**SUSPICIOUS ACTIVITY / FLOOD**, MEDIUM confidence for "flood"; **not** "confirmed DDoS" without external flow/ISP data.

### What would change the conclusion

ISP/flow data showing many sources → DDoS. A single internal host or a load test → DoS/misconfiguration. A routing loop or bad NIC → not an attack.

### Recommendation

Preserve evidence, engage the ISP, enable SYN cookies, add RAW early drops and rate limits, close exposed services, monitor conntrack.

**ATT&CK:** T1498, T1499.

---

## Scenario 4 — Open DNS resolver used for amplification

### Evidence

```text
[admin@edge-rtr] > /ip/dns/print
  allow-remote-requests: yes
  servers: 203.0.113.53

[admin@edge-rtr] > /ip/firewall/filter/print
... no rule dropping UDP/TCP 53 from WAN ...

[admin@edge-rtr] > /interface/monitor-traffic interface=ether1 once
        rx-rate: 120.0Mbps
        tx-rate: 780.0Mbps
   rx-packets-per-second: 22,000
   tx-packets-per-second: 180,000
```

Outbound traffic is much larger than inbound, dominated by UDP/53.

### Analysis

- `allow-remote-requests=yes` plus no WAN restriction makes the router a potential open resolver.
- Asymmetric inbound small queries / outbound large responses is consistent with amplification.
- Source addresses may be spoofed; do not attribute to the apparent source.

### Classification

**CONFIGURATION WEAKNESS + SUSPICIOUS ACTIVITY**, HIGH confidence for the open resolver; MEDIUM for amplification without packet capture.

### What would change the conclusion

A firewall rule we did not see blocking 53 from WAN, or the router not being the resolver (another device is). Verify the full rule set and interface membership.

### Recommendation

Block 53 from WAN, disable remote requests if not needed, rate-limit DNS, monitor outbound asymmetry, consider BCP38 at the ISP.

**ATT&CK:** T1498.002.

---

## Scenario 5 — ARP spoofing suspicion

### Evidence

```text
[admin@edge-rtr] > /ip/arp/print
Flags: D - DYNAMIC; C - COMPLETE
 #   ADDRESS         MAC-ADDRESS        INTERFACE
 0 DC 192.168.88.1    00:00:5E:00:53:AA  bridge
 1 DC 192.168.88.1    00:00:5E:00:53:BB  bridge
 2 DC 192.168.88.10   00:00:5E:00:53:10  bridge
```

A user reports intermittent connectivity and a certificate warning.

### Analysis

- Two MAC addresses for the gateway IP is suspicious.
- It can be legitimate: VRRP virtual MAC, failover, a replacement NIC, or a stale entry.
- RouterOS does not show which host is authoritative; the ARP table is local to the router.

### Classification

**SUSPICIOUS ACTIVITY**, LOW/MEDIUM confidence. **Not** confirmed ARP spoofing.

### What would change the conclusion

Switch DAI/DHCP-snooping logs, a packet capture showing gratuitous ARP, or a second vantage point. If the legitimate gateway MAC is 00:00:5E:00:53:AA and .BB is an unknown host, confidence rises.

### Recommendation

Check switch port security/DAI, isolate the suspect port, use static ARP for the gateway if practical, segment the network, deploy an IDS.

**ATT&CK:** T1557.

---

## Scenario 6 — Rogue DHCP

### Evidence

```text
2026-11-11 09:02:11 dhcp,info defconf assigned 192.168.88.50 for 00:00:5E:00:53:50
2026-11-11 09:02:12 dhcp,info defconf assigned 192.168.88.51 for 00:00:5E:00:53:51
2026-11-11 09:02:12 dhcp,info defconf assigned 192.168.88.52 for 00:00:5E:00:53:52
```

Users report a gateway of 192.168.88.254 instead of 192.168.88.1.

### Analysis

- The router's own DHCP server is assigning leases, but clients are using a different gateway.
- That suggests another DHCP server on the segment, or a static misconfiguration.
- RouterOS logs its own leases; it does not log rogue offers.

### Classification

**SUSPICIOUS ACTIVITY / POSSIBLE ROGUE DHCP**, LOW/MEDIUM confidence from RouterOS alone.

### What would change the conclusion

Switch DHCP-snooping logs, a packet capture of DHCP OFFERs, or the MAC/port of the rogue server. Then HIGH confidence.

### Recommendation

Enable DHCP snooping and port security on switches, trust only the legitimate server port, isolate the suspect device, verify client configurations.

**ATT&CK:** T1557, T1200 (hardware additions) may apply.

---

## Scenario 7 — Distributed credential stuffing against API

### Evidence

```text
2026-11-11 11:02:44 system,error,critical login failure for user auditor from 192.0.2.77 via api
2026-11-11 11:03:12 system,error,critical login failure for user api from 198.51.100.23 via api
2026-11-11 11:04:01 system,error,critical login failure for user admin from 203.0.113.90 via api
2026-11-11 11:05:22 system,error,critical login failure for user backup from 192.0.2.88 via api
```

Each source has 1–2 failures; total 200 failures across 60 sources and 12 usernames over 40 minutes.

### Analysis

- Low per-source rate, many sources, many usernames: distributed password spraying/credential stuffing.
- Per-source thresholds will not catch it.
- If one succeeds, the source may be a proxy or compromised host.

### Classification

**ATTEMPTED ATTACK**, MEDIUM confidence without external correlation; HIGH if the pattern is confirmed across routers/SIEM.

### What would change the conclusion

A known API client using stale credentials, or a monitoring system rotating secrets. Verify accounts and sources.

### Recommendation

Disable API on WAN, use API-SSL with a read-only account, restrict sources, add centralized correlation, rotate credentials, alert on distributed failure patterns.

**ATT&CK:** T1110.003, T1110.004.

---

## Scenario 8 — Legitimate backup mistaken for exfiltration

### Evidence

```text
2026-11-11 02:00:00 firewall,info OUT-CONN forward: in:bridge out:ether1,
    proto TCP, 192.168.88.20:49881->198.51.100.50:443, len 60
... 40 similar connections over 20 minutes ...
[admin@edge-rtr] > /interface/monitor-traffic interface=ether1 once
        rx-rate: 40.0Mbps
        tx-rate: 310.0Mbps
```

### Analysis

- Large outbound transfer at 02:00 to a single external IP:443.
- This is exactly what a nightly backup looks like.
- Check the source host role, the destination reputation, the schedule, and the change calendar.

### Classification

**NORMAL / FALSE POSITIVE**, HIGH confidence if the backup schedule and destination are confirmed.

### What would change the conclusion

The source host is not a backup server, the destination is unknown, the transfer is outside schedule, or the volume is anomalous. Then investigate as possible exfiltration.

### Recommendation

Document approved backup destinations, baseline egress, alert on deviations, use flow data to distinguish backup from exfiltration.

**ATT&CK:** T1041 (only if malicious).

---

## Scenario 9 — Router persistence after compromise

### Evidence

```text
[admin@edge-rtr] > /user/print
 #   NAME        GROUP   ADDRESS
 0   admin       full
 1   svc-backup  full    198.51.100.99

[admin@edge-rtr] > /system/scheduler/print
 #   NAME     START-TIME  INTERVAL  ON-EVENT
 0   sync     00:00:00    5m        /system/script/run sync

[admin@edge-rtr] > /system/script/print
 #   NAME   OWNER  POLICY
 0   sync   admin  ftp,reboot,read,write,policy,test,password,sniff,sensitive
```

The owner did not create `svc-backup`, `sync`, or the scheduler.

### Analysis

- Unauthorized full-privilege account + scheduler + script = persistence.
- The script's policies are excessive.
- Combined with an unexplained login, this is strong evidence of compromise.

### Classification

**CONFIRMED COMPROMISE**, HIGH confidence (if the owner confirms the objects are unauthorized and the login is unexplained).

### What would change the conclusion

A documented automation project created these objects. Verify with the owner and change tickets.

### Recommendation

Preserve evidence, disable/remove the objects after capture, rotate all credentials and keys, patch the entry vector, rebuild if integrity is uncertain, monitor for recurrence.

**ATT&CK:** T1136, T1053.003, T1059.

---

## Scenario 10 — Possible C2 beaconing

### Evidence

```text
2026-11-11 02:40:12 firewall,info OUT-CONN forward: in:bridge out:ether1,
    proto TCP, 192.168.88.10:51044->198.51.100.99:443, len 60
2026-11-11 02:45:13 firewall,info OUT-CONN forward: in:bridge out:ether1,
    proto TCP, 192.168.88.10:51051->198.51.100.99:443, len 60
2026-11-11 02:50:14 firewall,info OUT-CONN forward: in:bridge out:ether1,
    proto TCP, 192.168.88.10:51058->198.51.100.99:443, len 60
2026-11-11 02:55:15 firewall,info OUT-CONN forward: in:bridge out:ether1,
    proto TCP, 192.168.88.10:51065->198.51.100.99:443, len 60
```

Connections every 5 minutes to the same IP:443, small and regular.

### Analysis

- Periodicity + same destination + small transfers is consistent with beaconing.
- It is also consistent with a health check, license check, or telemetry.
- RouterOS logs show new connections only if a logging rule matches; they do not show payload or TLS SNI.

### Classification

**SUSPICIOUS ACTIVITY**, MEDIUM confidence. Needs flow/threat-intel/endpoint correlation.

### What would change the conclusion

The destination is an approved SaaS/telemetry endpoint, or the endpoint's EDR shows a legitimate agent. Then NORMAL. If threat intel flags the IP or the host shows malware, then HIGH.

### Recommendation

Identify the process on 192.168.88.10, check DNS/TLS logs, compare with baseline, block at egress only after confirming, preserve evidence.

**ATT&CK:** T1071.001, T1571.

---

## Summary table

| # | Scenario | Classification | Confidence |
|---|---|---|---|
| 1 | SSH brute force + success | Attempt → possible unauthorized access | HIGH/MEDIUM |
| 2 | Vertical SYN scan | Attempted attack (recon) | MEDIUM/HIGH |
| 3 | SYN flood | Suspicious flood, not confirmed DDoS | MEDIUM |
| 4 | Open resolver amplification | Weakness + suspicious | HIGH/MEDIUM |
| 5 | ARP spoofing | Suspicious | LOW/MEDIUM |
| 6 | Rogue DHCP | Possible | LOW/MEDIUM |
| 7 | Distributed stuffing | Attempted attack | MEDIUM |
| 8 | Backup | Normal/false positive | HIGH |
| 9 | Persistence | Confirmed compromise | HIGH |
| 10 | Beaconing | Suspicious | MEDIUM |

---

## Sources

- Log: <https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log>
- Firewall: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall>
- Connection tracking: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/connection-tracking>
- DDoS protection: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/user-guides/ddos-protection>
- SSH brute-force protection: <https://manual.mikrotik.com/docs/firewall-and-quality-of-service/user-guides/bruteforce-prevention>
- MITRE ATT&CK: <https://attack.mitre.org/>
- NIST CSF 2.0: <https://www.nist.gov/cyberframework>
