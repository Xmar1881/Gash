<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/tls-cert-deep.md
What: Unit-test report for the proto TLS certificate/chain depth facts (GASH-024, Faz 2).
Why: Documents local-derivation contract, reuse of the observed handshake, and no-revocation boundary.
-->

# Metrics: tls-cert-deep (proto, GASH-024)

## Overview

Engine infra recon (`engine.runInfraRecon`, `--tls-audit-deep`, `tls`
detector + https target; no `--active` needed). `internal/proto/tls.go`
derives certificate/chain facts locally from an observed handshake — reused
from the TLS recon observation when it already ran, otherwise one extra
local handshake per scan; the two legacy-version probes are unchanged.
Signals (all `confirmed`, plugin `proto-tls-deep`): RSA < 2048 (`high`) /
ECDSA < 256 (`medium`) / DSA (`high`) keys → `tls-weak-key` (CWE-326);
MD2/MD5/SHA-1 signatures → `tls-weak-signature` (`medium`, CWE-327);
CA:TRUE leaf → `tls-leaf-is-ca` (`high`); chain not verifiable against the
host's local system roots → `tls-untrusted-chain` (`medium`, skipped for
self-signed leaves); no SAN at all with a CN → `tls-no-san` (`low`);
TLD-level or single-label wildcard → `tls-wildcard-broad` (`low`);
validity > 398 days → `tls-long-validity` (`low`). No OCSP/CRL revocation
lookup is performed and no certificate is stored.

## Evidence Standard

`tls-untrusted-chain` distinguishes `incomplete` (server did not send an
intermediate the local verify needed) from `untrusted` (local roots cannot
build any verified chain); `invalid` (e.g. expired) and `verified` never
produce this signal. Evidence carries `key_algo`/`key_bits`, `sig_algo`,
`leaf_is_ca`, `chain_status`/`chain_err` (sanitized, ≤300 chars),
`has_san`/`leaf_cn`, `wildcard_names`, `validity_days`, plus the base TLS
observation fields. All findings are GASH-024/`confirmed`; the pre-existing
signals (expired, expiring, self-signed, hostname-mismatch, tls10/tls11,
weak-cipher) are never duplicated.

## Unit Cases (no fixtures; loopback only)

- Classifier tables: `weakKeyReason` 7 cases (RSA-1024 high, RSA-2048
  silent, ECDSA P-224 medium, P-256 silent, DSA high, unknown bit length
  silent, nil silent); `weakSignatureReason` 8 algorithm cases + nil;
  wildcard/SAN 6-name classification with broad set exactly `*.com` + `*.`
  and multi-label wildcards (`*.example.com`, `*.co.uk`) silent; IP-literal
  SAN counts as SAN, CN-only does not; `certValidityDays` 3 cases.
- Chain classifier (real signed certs, 6 cases): trusted root → `verified`;
  issuer present but roots untrusted → `untrusted`; issuer absent →
  `incomplete`; self-signed leaf → `untrusted` (not `incomplete`); expired
  leaf → `invalid`; nil leaf → silent.
- Synthetic TLSResult: exactly the 7 new signals fire once, severities and
  CWEs as specified; the 7 pre-existing signal names are absent; nil result
  → 0 findings. Self-signed observation never re-reports
  `tls-untrusted-chain`; a healthy observation (verified chain, ECDSA-256,
  SHA-256, SANs, 90 days) → 0 findings.
- Live loopback servers (real handshakes): RSA-1024 self-signed → fields
  populated (`RSA`/1024, non-empty sig algo, `!IsCA`, IP-only SAN so
  `HasSAN` true, `SelfSigned` true, `ChainStatus=untrusted`, validity
  199–201 days), `tls-weak-key` `high` fires, `tls-untrusted-chain` does
  not; CA:TRUE RSA-2048 → `tls-leaf-is-ca` fires.
- Engine (`--tls-audit-deep`): weak RSA-1024 server → `tls-weak-key` high,
  no `tls-no-san` for an IP-SAN cert, no `tls-untrusted-chain` for
  self-signed, `tls_deep_checks ≥ 1`; CA leaf → `tls-leaf-is-ca`;
  observation-reuse test closes the server before calling the deep branch
  and still gets `tls-weak-key` from the cached observation (proves no
  re-dial for cert facts).
- Commands: `go test ./internal/proto/ -run 'TLSDeep|WeakKey|WeakSignature|Wildcard|CertValidity|ClassifyChain|CheckTLSDeep' -v`
  and `go test ./internal/engine/ -run 'TLSDeep' -v`.

## Corpus Result

Proto TLS checks read no HTTP bodies; corpus `firm` is unaffected by
construction.

## Lab Result

Hermetic lab is the loopback TLS servers above (in-process
`x509.CreateCertificate`, no external network). No real-target recall is
claimed.

## Precision

Unit true positives: 7 signal classes (synthetic) + 2 live-server signal
cases + 3 engine cases; false positives 0 within scope (self-signed
untrusted-chain duplicate, healthy observation, IP-SAN-as-no-SAN, nil, and
expired→invalid chain paths all verified silent). Precision 1.00
(unit-scoped, not real-target recall).

## Recall

All implemented signals fire in unit scope; false negatives 0 in scope.
Signals outside the implemented set (revocation, hostname policies beyond
`VerifyHostname`, OCSP stapling) are deliberately absent and not covered.

## Gate Verdict

PASS (unit-scoped). Engine infra recon has no plugin ID or fixtures, so
`TestMetricGate` does not apply; the gate is `go test ./...` plus
`go vet ./...`, both green.

## Limitations

- Chain status depends on the **host's local system root store**: private
  roots are not consulted, and an AIA-fetchable intermediate that the
  server did not send reads as `incomplete`.
- No revocation checking (OCSP/CRL/stapling) — a revoked-but-otherwise-valid
  chain stays `verified`.
- Weak-key detection requires an observable algorithm and bit length;
  unknown sizes stay silent rather than guessing.
- DSA is flagged as a class without claiming exploitability; SHA-1
  signatures remain common in legacy chains and the signal is hygiene, not
  a break claim.
- The 398-day validity threshold mirrors browser policy and is a hygiene
  signal, not a compliance verdict.
- `tls-no-san` means *no SAN entries at all*; an IP-only SAN cert does not
  fire even though it is unusable for DNS clients.

## Dataset

No fixtures. Hermetic unit tests only (synthetic certs + loopback servers).
Re-run the commands above; any behaviour change must update this report,
never imply real-target recall.
