<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/ssh-version-advisories.md
What: Unit-test report for the proto SSH banner version to advisory mapping (GASH-056, Faz 2).
Why: Documents the curated table contract and its FP/FN boundaries without real-target claims.
-->

# Metrics: ssh-version-advisories (proto, GASH-056)

## Overview

Engine infra recon (`engine.runInfraRecon`, `--ssh-audit`, `--active` +
`ssh` detector). `internal/proto/ssh_versions.go` parses the `OpenSSH_x.y[pN]`
token from the same RFC 4253 banner read as GASH-052 (no extra socket, no
KEX, no auth) and matches it against a small curated server-side advisory
table. Every match is aggregated into exactly one GASH-056 (CWE-1395)
finding per host; severity is the highest matched entry (currently one
`high` entry, the rest `medium`), and confidence is capped at `tentative`
because the banner is the server's own claim and vendor backports are
invisible. Non-OpenSSH banners and versions outside the table stay silent.
When GASH-056 fires, the engine drops the generic `ssh-old-software` signal
from GASH-052 for that banner; the protocol 1.x finding is always kept.

Curated table (bounds locked by tests):

| CVE | Bounds | Severity |
|---|---|---|
| CVE-2024-6387 (regreSSHion) | 8.5p1 ≤ v ≤ 9.7p1 | high |
| CVE-2023-48795 (Terrapin) | v < 9.6 | medium |
| CVE-2021-41617 | v < 8.8p1 | medium |
| CVE-2018-15473 | v ≤ 7.7 (patch-independent) | medium |
| CVE-2016-10012 | v < 7.4 | medium |
| CVE-2015-6564 | v < 7.0 | medium |
| CVE-2015-5600 | v < 7.0 | medium |

## Evidence Standard

Finding carries `software`, `software_version` (normalized `major.minor pN`),
`cves` (comma list, table order), `cve_count`, `signal`
(`ssh-vulnerable-version`), and `note` (backport warning). Description names
the matched CVEs and states the mapping is heuristic. No exploit attempt,
no version-specific probe, and no claim beyond the table is made.

## Unit Cases (no fixtures; no external SSH)

- Parser table: 7 valid forms (bare `x.y`, `pN`, leading/trailing spaces,
  distro suffixes `Debian-2+deb12u2` / `Ubuntu-3ubuntu0.4`, vendor suffix
  `-hpn14v15`) and 15 malformed forms (empty, `OpenSSH_`, missing minor,
  missing patch number, `openssh_` lowercase, full banner line, absurd
  version numbers) → malformed never produce a version claim.
- Boundary table (9 versions): `9.8p1` silent (outside table); `9.7p1` →
  regreSSHion only, `high`; `9.6` → regreSSHion only (Terrapin fixed);
  `8.5p1` → regreSSHion lower bound inclusive, `high`; `8.4p1` → no
  regreSSHion, `medium`; `8.8p1` → no CVE-2021-41617; `7.7p2` → CVE-2018-15473
  yes (minor-inclusive), CVE-2016-10012 no; `7.0` → the two `<7.0` entries
  excluded, four others matched; `6.9` → six matches, highest `medium`.
- Aggregation/vendor suffixes: Debian `9.2p1` → exactly 2 CVEs,
  `software_version=9.2p1`, `cve_count=2`; Ubuntu `8.9p1` → regreSSHion yes,
  CVE-2021-41617 no.
- Silent set (11 inputs): `9.8p1`, `10.0`, empty, Dropbear, Cisco, Sun_SSH,
  free-text banner, and four malformed OpenSSH tokens → zero findings; the
  target string is passed through unchanged (caller owns attribution).
- Engine live mock (`SSH-1.5-OpenSSH_3.9p1`): exactly one dial;
  `ssh-proto-1` (GASH-052) kept, `ssh-old-software` dropped, GASH-056
  emitted. Engine dedup mock (`SSH-2.0-OpenSSH_8.4p1`): exactly one finding
  total, GASH-056 `tentative`/CWE-1395 with `software_version=8.4p1`.
- Commands: `go test ./internal/proto/ -run 'OpenSSH|SSHVersion' -v` and
  `go test ./internal/engine/ -run 'InfraReconSSH' -v`.

## Corpus Result

Proto SSH checks read no HTTP bodies; corpus `firm` is unaffected by
construction.

## Lab Result

Hermetic lab is the loopback banner mock above (RFC 4253 line framing, no
external SSH). No real-target recall is claimed.

## Precision

Unit true positives: 9 boundary cases + 2 vendor/aggregation cases + 2 engine
live cases; false positives 0 (silent set, malformed set, and dedup case all
produce nothing unexpected). Precision 1.00 (unit-scoped, not real-target
recall). Backport blind spots are false positives by design and documented
below.

## Recall

All versions inside the seven table bounds match in unit scope; false
negatives 0 in scope. Everything outside the curated table (including
backported distro builds) is deliberately not covered.

## Gate Verdict

PASS (unit-scoped). Engine infra recon has no plugin ID or fixtures, so
`TestMetricGate` does not apply; the gate is `go test ./...` plus
`go vet ./...`, both green.

## Limitations

- Banner-only heuristic: distro backports are invisible, so a patched
  `8.9p1` still matches regreSSHion and a vulnerable-but-renamed build does
  not. Banners are also spoofable by honeypots or proxies.
- The table is intentionally tiny; absence of a match is not a clean bill of
  health for the version.
- Only `OpenSSH_` tokens are parsed (Dropbear/Cisco/etc. produce nothing).
- Vendor suffix parsing is tolerant but never consulted for the match, so
  `9.2p1 Debian-2+deb12u2` matches on `9.2p1` alone.
- No CVE severity beyond the table, no exploitability judgment, no
  version-specific verification probe.

## Dataset

No fixtures. Hermetic unit tests only (loopback mock + tables). Re-run the
commands above; any behaviour change must update this report, never imply
real-target recall.
