# RouterOS API and REST API for Safe Security Analysis

**Scope:** How to read RouterOS state over the API and REST API without changing it, including protocol basics, allowlisting, pagination, and credential safety.
**Last reviewed:** 2026-11-11
**Applies to:** RouterOS v6 and v7 (API), RouterOS v7 (REST API).

---

## 1. Why the API matters for security work

The API gives structured access to the same configuration and state as the CLI. That is valuable for audits because it avoids screen-scraping and produces machine-readable evidence. It is also dangerous: the API can execute almost any CLI command, including reboot and configuration changes. The protocol has no built-in "read-only" mode. Read-only behavior must come from the account, a proxy, or the client.

Authoritative reference: <https://manual.mikrotik.com/docs/developer-guides/api>

---

## 2. Transport and exposure

| Service | Default port | Encryption | Notes |
|---|---|---|---|
| `api` | 8728/TCP | None | Credentials and data are cleartext. Never use over an untrusted network. |
| `api-ssl` | 8729/TCP | TLS | Requires a certificate for a usable TLS session. |
| `www` | 80/TCP | None | REST over HTTP; cleartext. |
| `www-ssl` | 443/TCP | TLS | REST over HTTPS; requires a certificate. |

Check exposure:

```ros
/ip/service/print
```

Expected shape:

```text
Flags: X - DISABLED
Columns: NAME, PORT, ADDRESS, CERTIFICATE
#   NAME       PORT  ADDRESS
0   ftp          21
1   ssh          22  192.0.2.0/24
2   telnet       23
3 X www          80
4   www-ssl     443  cert=edge-cert
5   winbox     8291  192.0.2.0/24
6 X api        8728
7   api-ssl    8729  cert=edge-cert
```

Security interpretation:

- `api` enabled and reachable from WAN is a critical exposure: cleartext credentials.
- `api-ssl` without a certificate may fail TLS handshakes with modern clients (the manual notes anonymous DH ciphers are rejected).
- `available-from` restricts which clients are served, but the TCP port still accepts connections. Firewall rules are the real block.
- Disabling `www` while leaving `www-ssl` is reasonable if REST is needed.

---

## 3. API protocol essentials

### 3.1 Sentences and words

- A **sentence** is a sequence of words terminated by a zero-length word.
- Each word is length-encoded followed by its bytes.
- The first word is the **command word**, beginning with `/`.
- Attribute words begin with `=`, for example `=chain=input`.
- Query words begin with `?`, for example `?chain=input`.
- Replies begin with `!re` (data), `!done` (end), `!trap` (error), or `!fatal` (connection closing).

CLI paths are converted to API command words by replacing spaces with slashes:

```text
CLI:  /ip firewall filter print
API:  /ip/firewall/filter/print
```

### 3.2 Login

Modern RouterOS (v6.43+ and all v7) accepts a plain login sentence over the API:

```text
/login
=name=sec-auditor
=password=<secret>
```

Older v6 may return a challenge (`=ret=<challenge>`) and expect a legacy MD5 response. Do not implement legacy crypto unless you must support an old device. Prefer a modern v6.49/v7 release and API-SSL.

Login is a state-changing operation in the protocol sense (it creates a session), but it does not change router configuration. It is unavoidable for API access. Treat it as the only permitted non-read command.

### 3.3 Replies

```text
!re
=chain=input
=action=accept
=connection-state=established,related
=bytes=123456
=packets=789
!done
```

- `!re` can repeat many times. Read until `!done`.
- `!trap` means the command failed; do not retry with a more permissive command.
- `!fatal` means the session is closing; reconnect only if authorized.

### 3.4 Queries and `.proplist`

The manual documents that `print` and `getall` accept query words, evaluated in order:

```text
/ip/firewall/filter/print
?chain=input
```

`.proplist` limits returned properties:

```text
/ip/firewall/filter/print
=.proplist=chain,action,connection-state,bytes,packets,comment
```

Why this matters:

- Fewer fields means less sensitive data and less bandwidth.
- Some properties are expensive to read (file contents, performance counters). Omitting `.proplist` can be slow.
- Never request `password`, `secret`, `private-key`, `pre-shared-key`, `passphrase`, or `key`.

---

## 4. Read-only allowlist

The API has no read-only mode, so enforce one in the client or proxy.

### 4.1 Allowed command pattern

```text
^/(system|log|ip|ipv6|interface|user|snmp|certificate|ppp|radius|tool)
 [a-z0-9/_-]* /(print|getall|getone)$
```

Use exact menu paths in production, not only a regex. The `tool` root is risky: it contains `fetch`, `ping`, `traceroute`, `torch`, `sniffer`, and `bandwidth-test`. Prefer excluding `tool` entirely from the allowlist.

### 4.2 Explicitly forbidden command words

```text
/system/reboot
/system/shutdown
/system/reset-configuration
/system/backup/save
/export
/import
/system/package/update
/system/routerboard/upgrade
/ip/firewall/filter/add
/ip/firewall/filter/set
/ip/firewall/filter/remove
/ip/firewall/filter/move
/ip/firewall/filter/enable
/ip/firewall/filter/disable
/ip/firewall/address-list/add
/ip/firewall/address-list/remove
/ip/firewall/connection/remove
/log/print=file=...
/user/add
/user/set
/user/remove
/user/active/listen
/interface/vlan/remove
/tool/fetch
/tool/ping
/tool/traceroute
/tool/torch
/tool/sniffer
/tool/bandwidth-test
/tool/traffic-generator
```

`/user/active/listen` is a read operation but long-running and streaming. Strict mode uses a bounded `/user/active/print` snapshot instead.

### 4.3 Attribute-level controls

Reject attributes named:

```text
file, file-name, save, export, backup, restore, script, run, execute,
interval, duration, password, secret, private-key, pre-shared-key
```

Rationale: `print file=...` writes a file on the router, which is a state change and can destroy or alter evidence. Accepting arbitrary attributes lets a "read" become a write.

### 4.4 Pagination and volume

- Cap rows per call (for example 500).
- Use `?` queries to narrow by chain, list, address, port, or state.
- Never pull the full `/ip/firewall/connection` table on a busy router. Use `count-only` first, then sample by specific criteria.
- Set a client-side timeout and cancel the command if it exceeds it.
- Do not run multiple heavy reads concurrently.

---

## 5. Recommended read calls

### 5.1 System

```text
/system/resource/print
/system/identity/print
/system/routerboard/print
/system/package/print
/system/clock/print
/system/ntp/client/print
/system/device-mode/print
/system/history/print
```

### 5.2 Firewall and NAT

```text
/ip/firewall/filter/print
/ip/firewall/filter/print
=stats=
/ip/firewall/raw/print
/ip/firewall/nat/print
/ip/firewall/mangle/print
/ip/firewall/address-list/print
/ip/firewall/connection/tracking/print
/ip/firewall/connection/print
?dst-port=22
```

Attribute syntax varies by client library. In raw API, `=stats=` is an empty attribute. In a client library, use the library's equivalent.

### 5.3 Services and users

```text
/ip/service/print
/user/print
/user/group/print
/user/active/print
/user/ssh-keys/print
/snmp/print
/snmp/community/print
/ip/cloud/print
```

### 5.4 Logs

```text
/log/print
?topics~account
```

The API query language supports pattern matching with `~`. If your client library does not expose it, fetch a bounded recent set and filter locally. Do not fetch the entire log without a limit.

---

## 6. REST API (v7 only)

REST is available on `/rest` through the web server. Use HTTPS (`www-ssl`) with a trusted certificate. The REST API maps HTTP verbs to RouterOS commands:

| HTTP | Meaning | Read-only? |
|---|---|---|
| `GET` | Read/print | Yes |
| `POST` | Add | No |
| `PATCH` | Set/change | No |
| `DELETE` | Remove | No |

### 6.1 Safe HTTPS read

Illustrative only. Do not put a password in shell history. Use a protected netrc file or a secret manager.

```bash
curl --silent --show-error \
  --cacert ./router-ca.pem \
  --netrc-file ./.router-netrc \
  "https://192.0.2.1/rest/ip/firewall/filter"
```

`.router-netrc` (mode `0600`, never committed):

```text
machine 192.0.2.1
  login sec-auditor
  password <secret>
```

Expected JSON (abridged, synthetic):

```json
[
  {
    ".id": "*1",
    "chain": "input",
    "action": "accept",
    "connection-state": "established,related,untracked",
    "comment": "defconf: accept established,related,untracked"
  },
  {
    ".id": "*2",
    "chain": "input",
    "action": "drop",
    "in-interface-list": "!LAN",
    "comment": "defconf: drop all not coming from LAN"
  }
]
```

### 6.2 REST safety rules

- Allow only `GET`.
- Validate the path against the same allowlist as the API.
- Reject `?file=`, `?save=`, `?export=`.
- Never disable certificate verification.
- Do not send credentials over HTTP.
- Rate-limit and cap response size.

---

## 7. Credential handling

- Prefer a dedicated read-only account (`read,api,rest-api,ssh,winbox,web`, no `write`/`policy`/`reboot`/`test`/`sensitive`).
- Store the secret in a secret manager or a `0600` file outside the repository.
- Never place credentials in a URL, query string, command-line argument, log, or report.
- Never log the `=password=` attribute or the Authorization header.
- Rotate the account if a secret is exposed.
- Review `/log/print where topics~"account"` after an audit for unexpected logins.

See `references/read-only-safety.md` for the full contract.

---

## 8. Version and compatibility notes

| Feature | v6 | v7 |
|---|---|---|
| API 8728/8729 | Yes | Yes |
| Plain `/login` with name/password | v6.43+ | Yes |
| Challenge-response login | Older v6 | No (modern clients use plain over TLS) |
| REST API | No | Yes |
| `.proplist` | Yes | Yes |
| Query words | Yes | Yes |
| CEF log export | No | 7.18+ |
| `rest-api` user policy | No | Yes |

If a call fails with `unknown command` or `no such item`, do not assume a permission problem. Check the version and menu path first.

---

## 9. Example: safe read flow (language-neutral)

```text
1. Load target, time window, and credential from a protected source.
2. Open TLS (api-ssl 8729) or a local trusted connection.
3. Login. Record the login result, not the password.
4. For each command in the read plan:
   a. Validate it against the allowlist.
   b. Add .proplist and a row cap.
   c. Send, read until !done, and capture !trap.
   d. Store the raw result with a timestamp and command name.
5. Close the session.
6. Analyze offline. Never send a new command derived from untrusted log text.
```

---

## 10. Detection limitations

- The API sees configuration and state, not packet payloads.
- `print` returns the current state; it does not show history.
- `.proplist` can hide fields you later need; record which fields were requested.
- API counters are snapshots and can reset.
- A read-only account cannot see secrets protected by the `sensitive` policy, which is intentional.
- API-SSL certificate problems can cause silent connection failures; log the TLS error.
- REST JSON shape can differ between RouterOS releases; validate fields rather than assuming a schema.

---

## 11. Sources

- API: <https://manual.mikrotik.com/docs/developer-guides/api>
- Services: <https://manual.mikrotik.com/docs/system-information-and-utilities/services>
- User policies: <https://manual.mikrotik.com/docs/authentication-authorization-accounting/user>
- Log: <https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/log>
- Securing your router: <https://manual.mikrotik.com/docs/getting-started/securing-your-router>
- MikroTik security announcements: <https://mikrotik.com/supportsec>
