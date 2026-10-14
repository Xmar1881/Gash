<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/proto-checks.md
What: DNS/TLS/TCP protocol checks (package internal/proto, rules GASH-024/025/026).
Why: Protocol surface is outside the plugin HTTP path; passive-first, scope-bound.
-->

# Protocol Checks (DNS/TLS/TCP)

Protocol checks run inside `gash scan` as profile-gated recon (package
`internal/proto`). They are **passive observation plus safe read-only
probes** — no destructive control exists in this package.

| Check | Rule | Runs when | Confidence ceiling | Evidence |
|---|---|---|---|---|
| TLS cert expiry (≤30 d) / expired | GASH-024 (CWE-295) | `https` target, `tls` detector (safe+) | `confirmed` (date math on observed cert) | version, cipher, subject/issuer, notAfter, days_left |
| TLS self-signed / hostname mismatch | GASH-024 (CWE-295) | same | `confirmed` (observed fact) | chain_len, self_signed, hostname_err |
| TLS version < 1.2 | GASH-024 (CWE-327) | same | `confirmed` (negotiated fact) | tls_version |
| Missing SPF / DMARC | GASH-025 (CWE-693) | domain target, `dns` detector (safe+) | `firm` (resolver-dependent) | spf, dmarc records |
| TCP service banner | GASH-026 (CWE-200) | `--tcp-banner host:port` + `--active` + `tcp` detector | `tentative` (unverified banner) | banner (≤300 chars, sanitized) |

Profiles: `safe` and `standard`/`deep` enable `tls`+`dns`; `standard`/`deep`
additionally enable `tcp`. IP-literal targets skip DNS record checks
(no mail records expected); plain-`http` targets skip TLS.

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

## Deliberately absent (will not be added by default)

- **DNS zone transfer (AXFR) attempts**: only read queries (A/AAAA/TXT).
- **CAA checks**: the standard library offers no generic DNS query; no extra
  dependency is pulled in for v1 (documented gap, not silent).
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
