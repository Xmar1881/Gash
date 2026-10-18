<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/proto-checks.md
What: DNS/TLS/TCP/SSH/DB protocol checks (package internal/proto, rules GASH-024/025/026/027/052/053/054/055/056).
Why: Protocol surface is outside the plugin HTTP path; passive-first, scope-bound.
-->

# Protocol Checks (DNS/TLS/TCP/SSH/DB)

Protocol checks run inside `gash scan` as profile-gated recon (package
`internal/proto`). They are **passive observation plus safe read-only
probes** — no destructive control exists in this package. Infrastructure
recon (`ssh`, `db`, deep TLS) never authenticates with real credentials,
never sends commands or data-changing requests, and opens no socket outside
the resolved scope (fail-closed). Phase 1 adds two deeper observations: the
SSH KEXINIT algorithm lists (server declaration, never completing key
exchange) and a per-service unauthenticated-access probe that sends exactly
one harmless request with a fixed dummy identity (`gash_probe`). Phase 2
adds a curated banner→CVE map for OpenSSH (GASH-056) and local
certificate/chain facts under GASH-024 (weak key/signature, CA leaf,
untrusted/incomplete chain, CN-only, broad wildcard, overlong validity) —
all derived from the already-observed handshake, with no revocation
(OCSP/CRL) lookups.

| Check | Rule | Runs when | Confidence ceiling | Evidence |
|---|---|---|---|---|
| TLS cert expiry (≤30 d) / expired | GASH-024 (CWE-295) | `https` target, `tls` detector (safe+) | `confirmed` (date math on observed cert) | version, cipher, subject/issuer, notAfter, days_left |
| TLS self-signed / hostname mismatch | GASH-024 (CWE-295) | same | `confirmed` (observed fact) | chain_len, self_signed, hostname_err |
| TLS version < 1.2 / weak cipher | GASH-024 (CWE-327) | same | `confirmed` (negotiated fact) | tls_version (signal `tls10`/`tls11`), cipher_name, cipher_weakness |
| TLS legacy version acceptance | GASH-024 (CWE-327) | `--tls-audit-deep` + https target + `tls` detector (no `--active` needed) | `confirmed` (handshake accepted) | tls_version, signal `<tls10\|tls11>-supported`, outcome |
| Missing SPF / DMARC | GASH-025 (CWE-693) | domain target, `dns` detector (safe+) | `firm` (resolver-dependent) | spf, dmarc records |
| Missing / malformed CAA | GASH-027 (CWE-295) | domain target, `dns` detector (safe+) | `firm` (resolver-dependent) | caa records, signal, detail |
| TCP service banner | GASH-026 (CWE-200) | `--tcp-banner host:port` + `--active` + `tcp` detector | `tentative` (unverified banner) | banner (≤300 chars, sanitized) |
| SSH banner / protocol version | GASH-052 (CWE-327) | `--ssh-audit` + `--active` + `ssh` detector | `tentative` (server banner is a claim) | banner (≤255 B), protocol_version, software; signals `ssh-proto-1`, `ssh-old-software` (the generic signal is suppressed when GASH-056 fires for the same banner) |
| SSH known-vulnerable version → advisory map | GASH-056 (CWE-1395) | `--ssh-audit` + `--active` + `ssh` detector | `tentative` (banner claim + curated table; backports unchecked) | software, software_version, cves (comma list), cve_count; signal `ssh-vulnerable-version` |
| TLS cert/chain deep facts | GASH-024 (CWE-326/327/295) | `--tls-audit-deep` + https target + `tls` detector | `confirmed` (local derivation from the observed handshake) | key_algo/key_bits, sig_algo, leaf_is_ca, chain_status/chain_err, has_san/leaf_cn, wildcard_names, validity_days; signals `tls-weak-key`, `tls-weak-signature`, `tls-leaf-is-ca`, `tls-untrusted-chain`, `tls-no-san`, `tls-wildcard-broad`, `tls-long-validity` |
| Open DB port inventory | GASH-053 (CWE-200) | `--db-port-scan` + `--active` + `db` detector | `firm` (open port observed; service id is heuristic) | host, port, service, banner (≤300 chars, sanitized) |
| SSH weak KEX/hostkey/cipher/MAC algorithms | GASH-054 (CWE-327) | `--ssh-handshake-audit` + `--active` + `ssh` detector | `firm` (KEXINIT is the server's own declaration, deterministically observed) | ssh_version, kex_algorithms, host_key_algorithms, ciphers (c2s/s2c), macs (c2s/s2c), compression; signals `ssh-weak-kex`, `ssh-weak-hostkey`, `ssh-weak-cipher`, `ssh-weak-mac` |
| Unauthenticated DB access | GASH-055 (CWE-306) | `--db-unauth` + `--active` + `db` detector | `firm` (single harmless request proves no credential was demanded; no data read) | host, port, service, version, auth_method, banner, note; signals `db-unauth-<service>` |

Profiles: `safe` and `standard`/`deep` enable `tls`+`dns`; `standard`/`deep`
additionally enable `tcp`. The `ssh` and `db` detectors are enabled in
`standard`/`deep`/`aggressive` but stay dormant until their flags are passed
together with `--active` (see below). IP-literal targets skip DNS record
checks (no mail records expected); plain-`http` targets skip TLS.

## Explicit TCP banner probes

```sh
gash scan --target https://app.example.com --scope app.example.com \
  --active --tcp-banner app.example.com:22
```

- Repeatable `host:port`; malformed entries fail fast.
- Requires `--active` (read-only, but still an active probe).
- Each entry is scope-checked: the target host is always allowed, other
  hosts only via explicit `--scope` (fail-closed, no out-of-scope dials).
- Without `--active`, each entry becomes an auditable skip, not a finding.

## Infrastructure recon (SSH / DB ports / deep TLS)

```sh
gash scan --target https://app.example.com --scope app.example.com \
  --active --ssh-audit --db-port-scan --db-ports 5432,6379 --tls-audit-deep
```

Phase 1 adds two deeper observations (same gating discipline):

```sh
gash scan --target https://app.example.com --scope app.example.com \
  --active --ssh-handshake-audit --db-unauth --db-ports 5432,6379
```

- `--ssh-audit` (GASH-052): connects to `host:port` (default 22, or
  `--infra-target host:port`), reads the ≤255-byte RFC 4253 server banner,
  and closes. No KEX, no auth, no write. Banner is the server's own claim →
  findings cap at `tentative`; protocol banner `1.x` (including `1.99`
  compatibility) and an outdated OpenSSH family table
  (`OpenSSH_1`..`OpenSSH_7`, `OpenSSH_8.0`–`8.4`; no CVE claims) can add
  findings. Phase 2 (GASH-056): the banner software string is also matched
  against a small curated advisory table (regreSSHion CVE-2024-6387,
  Terrapin CVE-2023-48795, CVE-2021-41617, CVE-2018-15473, CVE-2016-10012,
  CVE-2015-6564, CVE-2015-5600) with inclusive/exclusive version bounds;
  one aggregated finding per host lists every matched CVE. When GASH-056
  fires, the generic `ssh-old-software` signal (GASH-052) is dropped for
  that banner to avoid duplicate/noisier reporting; the protocol 1.x
  finding is always kept. Requires `--active` and the `ssh` detector.
- `--db-port-scan` (GASH-053): dials each port from `--db-ports`
  (default 1433,1521,3306,5432,6379,9200,27017,11211,5984,9042), reads a
  bounded greeting (≤256 B, ≤500 ms window), closes. Never sends auth or
  commands. Open ports yield one `medium`/`firm` finding each; service
  naming is greeting heuristics with a port-map fallback (`unknown` if both
  miss). Requires `--active` and the `db` detector; list capped by
  `--max-infra-ports`.
- `--tls-audit-deep` (GASH-024): performs two separate TLS 1.0 / TLS 1.1
  handshake probes against the https target. An accepted legacy handshake is
  a deterministic observation → `medium`/`confirmed`
  (`<tls10|tls11>-supported`); rejected and indeterminate ("unknown")
  outcomes never become findings (no false positives). Phase 2 adds local
  certificate/chain facts from the observed handshake (reused from the TLS
  recon handshake when available; otherwise one local handshake): RSA < 2048
  (`high`) / ECDSA < 256 (`medium`) / DSA (`high`) keys → `tls-weak-key`;
  MD2/MD5/SHA-1 signatures → `tls-weak-signature` (`medium`); CA:TRUE leaf →
  `tls-leaf-is-ca` (`high`); chain not verifiable against local system roots
  → `tls-untrusted-chain` (`medium`, skipped for self-signed);
  no-SAN/CN-only → `tls-no-san`; wildcard covering a TLD or single label →
  `tls-wildcard-broad`; validity > 398 days → `tls-long-validity` (`low`).
  All of these are `confirmed` local derivations; **no OCSP/CRL revocation
  check is performed** and "untrusted" simply means local roots cannot build
  a verified chain. Needs the `tls` detector only.
- `--ssh-handshake-audit` (GASH-054): reads the RFC 4253 banner, then the
  server's `SSH_MSG_KEXINIT` (≤256 KB, deadline-bounded). Servers that do not
  send it unprompted get one fixed minimal client proposal (strong
  algorithms, fixed cookie) so the server's own reply can be observed. Name
  lists are parsed with hard caps; key exchange is **never completed and no
  auth is attempted**. Weak algorithm families (SHA-1 KEX/1024-bit group1,
  `ssh-dss`/`ssh-rsa` hostkeys, CBC/3DES/RC4/plaintext ciphers,
  MD5/SHA-1/umac-64 MACs) produce one `firm` finding per class; plaintext
  `none` cipher is `high`, everything else `medium`. Strong-only servers
  stay silent. Requires `--active` and the `ssh` detector.
- `--db-unauth` (GASH-055): one harmless request per supported service with
  the fixed dummy identity `gash_probe` — Redis `PING` (only `+PONG` proves;
  one optional `INFO server` read extracts the version), Memcached `version`,
  MongoDB legacy `OP_QUERY` `hello` on `admin.$cmd` (`ok:1` proves; code
  13/`unauthorized` means auth required), PostgreSQL `StartupMessage`
  (`AuthenticationOk`/trust proves; other auth requests are recorded, **no
  password is ever sent**), MySQL greeting metadata only (**no login is
  attempted, so no unauth claim**). Unsupported ports return a note without
  dialing. `Unauth` results yield one `high`/`firm` finding; auth-required
  and indeterminate results never fire. Requires `--active` and the `db`
  detector; port list shares `--db-ports` and the `--max-infra-ports` cap.
- All infra dials share `--infra-timeout` (5 s), `--infra-rate-limit`
  (5/s, 0 = unlimited), and `--infra-parallelism` (4); every target is
  scope-checked before any socket is opened, and out-of-scope entries
  become auditable skips (`no socket opened`). Gate failures (missing
  `--active`, detector disabled by profile) are auditable skips, never
  silent drops.
- `stats` gains `ssh_checks`, `db_ports_scanned`, `db_open_ports`,
  `tls_deep_checks`, `ssh_handshake_checks`, and `db_unauth_checks`
  counters.

## Deliberately absent (will not be added by default)

- **DNS zone transfer (AXFR) attempts**: only read queries (A/AAAA/TXT/CAA).
- **SSH key-exchange completion, auth, or command execution**: KEXINIT
  observation is supported (GASH-054) but no key material is derived, no
  auth method is attempted, and no channel or command is ever opened.
- **DB data access, commands, or credential use**: Phase 1 (`--db-unauth`)
  sends exactly one harmless request with the fixed dummy identity
  `gash_probe`; no real credentials, no queries beyond that single request
  (no Redis key enumeration, no Mongo collection access, no SQL), no writes,
  and MySQL login is never attempted.
- **Credential guessing / brute force / port knocking**: none of these
  exist anywhere in `internal/proto`.
- **CAA checks**: supported since 2026-10-16 via pinned `miekg/dns v1.1.73`
  (`internal/proto/caa.go`, GASH-027). Read-only TypeCAA query, 5 s cap,
  NXDOMAIN/timeout/SERVFAIL stay silent (no finding, no FP); malformed
  validation is intentionally narrow (empty tag, bad tag charset, empty
  value, bad iodef scheme) so unknown tags and flag bits never fire.
- **TCP payload interaction**: banner grab connects, reads ≤1 KB, sends
  nothing, and closes immediately. Web-port banner mode is not auto-run
  (TLS bytes would be false-positive noise).
- Certificate renewal, TCP writes, or any state-changing protocol action.

## Implementation notes

- TLS uses `InsecureSkipVerify` **as an observation method**: the handshake
  is inspected, never trusted — verdicts come from local rules (expiry
  math, chain shape, hostname check, negotiated version).
- Every check takes an `AllowHost` scope decision; `nil` means closed.
  Timeouts bound each check (default 10 s); errors yield no finding and
  never stop the scan.
