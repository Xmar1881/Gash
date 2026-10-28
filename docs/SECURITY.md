<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/SECURITY.md
What: Security and responsible-use policy for GASH operators and authors.
Why: Scans are invasive; the policy keeps testing authorized and contained.
-->

# Security Policy

## Purpose

GASH is an active security scanner. Probes change server state, trigger
alerts, and can cause outages when misused. This policy binds operators and
contributors alike.

## Responsible Use

- **Authorized targets only.** Scan only hosts, networks, and applications
  with written permission. Bug-bounty targets must stay inside the program
  scope; corporate targets need engagement paperwork; CI targets must be
  ephemeral preview environments.
- **Scope boundary (default same-site).** Without `--scope`, the engine stays
  on the target's registrable domain (eTLD+1) and its subdomains; cross-host
  redirects and crawl links are blocked, and the operator still owns
  authorization for every payload. For every non-local scan pass `--scope`
  with CIDR or domain entries; the engine then enforces the allowlist (plus
  DNS-rebinding pinning) at the proxy, and out-of-scope requests fail closed
  with `ErrScopeViolation`. `--allow-external` restores open mode and must be
  used deliberately.
- **OOB opt-in.** Out-of-band payloads force the target to call back over
  DNS or HTTP. OOB stays disabled unless `--oob-server` points at a
  self-hosted interaction server you control. Public interactsh endpoints
  are never the default. `--oob-server` requires `--active`.
- **Safe default option.** The CLI default profile is `standard` (controlled
  active checks); use `--profile safe` (GET/HEAD/OPTIONS only) in CI and
  against production. `--profile deep`, `--profile aggressive`, and
  `--active`-gated state-changing checks are explicit opt-ins. Do not enable
  them without authorization.

Misuse reports are handled as security issues; review rejects any plugin or
change that encourages unauthorized scanning.

## Reporting a Vulnerability

Email the maintainers with a minimal reproducer, affected version, and
impact assessment. Do not open a public issue for unpatched remote code
execution, sandbox escapes, or trust bypasses. Expect acknowledgment within
72 hours and coordinated disclosure.

## Trust and Supply Chain

- Tier 1 and Tier 2 plugins load automatically; Tier 3 binaries never run
  without `gash plugins trust` plus a matching sha256 pin and platform
  record (B10).
- World-writable plugin files or directories are refused at discovery.
- The plugin cache (`~/.gash/cache/plugins.db`) is keyed by mtime plus
  sha256 and regenerates silently on mismatch.
- Report trust bypasses, world-writable bypasses, or goja sandbox escapes
  as vulnerabilities, not as regular bugs.

## Secrets Handling

Evidence snippets redact `Authorization`, `Cookie`, `Set-Cookie`, and token
patterns at the reporter layer. Never paste live secrets into fixtures,
metrics reports, or issues. OOB tokens come from `--oob-token` or
`GASH_OOB_TOKEN`, never from checked-in config.

## Supported Versions

Only the latest minor release on the supported Go toolchain (`go1.27.3`,
minimum `go 1.26.0`) receives fixes. Older checkouts should upgrade before
reporting scanner vulnerabilities.
