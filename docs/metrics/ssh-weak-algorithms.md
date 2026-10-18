<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/ssh-weak-algorithms.md
What: Unit-test report for the proto SSH KEXINIT algorithm audit (GASH-054).
Why: Proves weak-algorithm grading fires only on server-declared names (no FP).
-->

# Metrics: ssh-weak-algorithms (proto, GASH-054)

## Overview

Engine infra recon (`engine.runInfraRecon`, `--ssh-handshake-audit`,
`--active` + `ssh` detector). `internal/proto/ssh.go` reads the RFC 4253
banner plus the server's `SSH_MSG_KEXINIT` (≤256 KB, deadline-bounded;
one fixed minimal client proposal when the server does not send it
unprompted). Key exchange is never completed and no auth is attempted.
Rule GASH-054 (CWE-327): weak KEX/1024-bit group1, `ssh-dss`/`ssh-rsa`
hostkeys, CBC/3DES/RC4/plaintext ciphers, MD5/SHA-1/umac-64 MACs →
one `firm` finding per class; plaintext `none` cipher is `high`, everything
else `medium`. Strong-only servers are silent; `confirmed` never fires
(KEXINIT is a declaration, not an executed exchange).

## Evidence Standard

Finding carries `host`, `port`, `ssh_version`, `kex_algorithms`,
`host_key_algorithms`, `ciphers` (`c2s=[...], s2c=[...]`), `macs`, 
`compression`, `signal` (`ssh-weak-kex`/`ssh-weak-hostkey`/
`ssh-weak-cipher`/`ssh-weak-mac`), `weak_algorithms`, `weakness`.
All lists sanitized and capped (≤2048 chars); cipher/MAC client and server
lists are merged into one class finding each. No CVE identifier is claimed.

## Unit Cases (no fixtures; no external SSH)

- Live mock, strong lists (+languages): all 10 name-lists parse in order
  (compression verified after language lists), 0 findings.
- Live mock, mixed weak lists: exactly 4 class findings (kex medium,
  hostkey medium, cipher `high` via 3DES/RC4, mac medium), each
  GASH-054/CWE-327/`firm` with populated `weak_algorithms`.
- Compression `none` alone: silent (not a cipher). Cipher list with
  `none`: 1 `high` finding, `weakness=plaintext-none`.
- Client-initiated path (server waits for the client proposal): observed
  and parsed (Dropbear-style mock).
- Malformed ×4 (truncated packet, oversized `packet_length`, wrong message
  type, silent server under a short deadline): error, no finding, no hang.
- Scope/IP/nil: nil `Allow` → error; deny → error; empty host → error;
  zero sockets accepted in all three.
- Classifier table: 19 weak-name cases match expected reason/severity
  (including `diffie-hellman-group14-sha1` → `sha1-kex` and
  `des-cbc` → `single-des`), 13 modern-name cases (incl.
  `diffie-hellman-group16-sha512`, `sntrup761x25519-sha512`, ETM-MACs)
  stay silent.
- Engine gates: `--active` off → `skipped (requires --active)`, zero dials;
  Safe profile → `detector ssh disabled`, zero dials; live run →
  `ssh_handshake_checks=1` and weak-kex + weak-hostkey findings.
- Command: `go test ./internal/proto/ -run 'SSH|Handshake' -v` and
  `go test ./internal/engine/ -run 'SSHHandshake' -v`.

## Corpus Result

Proto SSH checks read no HTTP bodies; corpus `firm` is unaffected by
construction.

## Lab Result

Hermetic lab is the loopback mock above (real KEXINIT wire framing,
RFC 4253 layout, no external SSH). No real-target recall is claimed.

## Precision

Unit true positives 7 finding-level (4 weak classes + 1 plaintext-none +
2 engine live signals) plus 19 classifier weak-name cases; false positives
0 (strong set, compression-`none`, malformed servers, and scope-denied
paths all produce nothing). Precision 1.00 (unit-scoped, not real-target
recall).

## Recall

Covered weak families all fire in unit scope; false negatives 0 in scope.
Recall 1.00 (unit-scoped); families outside the classifier's name list are
deliberately silent and not covered.

## Gate Verdict

PASS (unit-scoped). Engine infra recon has no plugin ID or fixtures, so
`TestMetricGate` does not apply; the gate is `go test ./...` plus
`go vet ./...`, both green.

## Limitations

- Algorithm classification is name-family heuristics; no CVE mapping and
  no cryptanalytic judgment beyond the recognized families.
- A server may advertise weak algorithms it would not actually negotiate
  first; the finding reports the declaration, not a negotiated result.
- `ssh-rsa`/`diffie-hellman-group14-sha1` findings are intent even when
  legacy-client compatibility justifies them.
- Servers that send KEXINIT only after a real client offer are observed
  via one fixed strong proposal; a server requiring more of the exchange
  produces an error, never a finding.

## Dataset

No fixtures. Hermetic unit tests only (loopback mocks + table). Re-run the
commands above; any behaviour change must update this report, never imply
real-target recall.
