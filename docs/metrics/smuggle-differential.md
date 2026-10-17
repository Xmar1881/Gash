<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/smuggle-differential.md
What: Precision and recall report for the raw-TCP request-smuggling differential probe.
Why: Proves GASH-033 (CWE-444) reports CL.TE/TE.CL desync at the dual-channel firm ceiling with zero single-channel findings.
-->

# Metrics: smuggle-differential (engine-recon, GASH-033)

## Overview

Engine-recon capability, plugin YOK. `smuggle.Scan` opens raw TCP sockets
(`net.DialTimeout`, TLS via `tls.Client` — `net/http` bypassed, it cannot
control chunk framing) and runs one control pair plus three ambiguous
(CL+TE) probes (CL.TE / TE.CL / TE.TE) on keep-alive connections: ambiguous
request first, then the byte-identical harmless follow-up GET. Control and
probe follow-ups are compared for status/body divergence (differential) and
follow-up latency delta (timing). Emits **GASH-033 request-smuggling
(CWE-444, severity high)** at most at `firm`. `--active` + `--aggressive`
gated; anything else is an auditable skip, never a finding. Scope
enforcement is opt-in: without `--scope` the probe dials the user-supplied
host (operator responsibility); with `--scope` the target must be in scope
or the probe skips with `ErrScopeViolation` and zero sockets.

## Evidence Standard

Rule GASH-033 (CWE-444). Oracle `smuggling-differential` (new discipline
name, no new confidence level): accept requires BOTH channels on the same
axis — follow-up status/body diverges from the control follow-up AND the
follow-up is delayed (>=500 ms delta) or times out. Ladder:

- `firm`: dual-channel divergence on >=1 probe kind + clean control pair.
  This is the ceiling; `confirmed` NEVER fires from this discipline alone.
- reject (no finding): single-channel signal only (delay without divergence
  or divergence without delay), broken control pair (timeout/5xx), WAF/block
  first response (`Untrusted` -> axis dropped), scope/gate skip.

Oracle choice rationale: smuggling proof is a framing-interpretation
difference plus a queuing delay on the same connection. The existing
`differential` (3/3 masked bodies) and `timing` (Mann-Whitney N>=3) oracles
do not model paired same-connection follow-ups, so a dedicated
`smuggling-differential` discipline encodes the dual-channel rule and the
firm ceiling in one place (`internal/smuggle/smuggle.go` `decide`).

## Fixtures

Raw-exchange fixtures under `internal/smuggle/testdata/` (mock-fixture
scoped, Tier 1 harness dışı — Tier 1 tek-istekli YAML ham soket
açamaz):

- Positive (`positive_01.txt`): vulnerable mock (CL/TE inconsistency:
  first 200/OK-first, follow-up delayed ~1000 ms + 400/desync-queued) ->
  `firm` finding, GASH-033/CWE-444.
- Negative (`negative_01.txt`): consistent mock (every response fast
  200/OK-clean) -> reject, no finding.
- Command: `go test ./internal/smuggle/ -v`

Unit mocks are localhost raw-TCP servers in `internal/smuggle/smuggle_test.go`
(no external traffic): TP on vulnerable mock, TN on consistent mock,
`ErrScopeViolation` + zero dials on scope-denied, skip + zero dials on
gate-off. Open mode (nil `Allow`) is dial-proofed without network via a
fake injected dialer: non-loopback targets (documentation IP) reach the
dial attempt instead of being refused, and the error surfaces without a
finding.

## Corpus Result

No `firm`/`confirmed` is constructible without dual-channel divergence:
bare status difference without delay rejects, delay without divergence
rejects, broken control rejects, WAF first response drops the axis. Covered
by `TestSmuggleSingleChannelRejects` plus the consistent-mock TN run.

## Lab Result

Procedure: serve the vulnerable mock behavior on localhost (or any
loopback lab app with a known CL/TE interpretation split), run
`gash scan --active --aggressive --scope 127.0.0.1 <localhost>`; expect one
high severity finding at `firm` with `divergent_kinds` artifact; against the
consistent app expect no GASH-033 and a `smuggle_requests` stat of 8.
Status: fixture-proofed (mock TP/TN above); live lab run pending manual
confirmation. Expected Precision 100 percent on this probe class.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. No finding above `tentative`
on consistent/negative paths (no finding at all); `confirmed` never fires
by construction.

## Dataset

- Dataset hash: `989568678e39dc6678ead7e935dc211338992e3fd2ab37cfb4aa4db25ccd3b27` (sha256 over the concatenated bytes of `internal/smuggle/testdata/*.txt` in sorted filename order).
- Samples: TP=1, FP=0, TN=1, FN=0. Fixture-only measurement (localhost raw-TCP mocks); lab pending above.

## Limitations

- Requires `--active` + `--aggressive` (aggressive profile); safe/standard/deep
  scans record an auditable skip, never a finding.
- Dials the user-supplied target (Nuclei/Burp smuggler model; written
  authorization required). With `--scope` set, an out-of-scope target gets
  `ErrScopeViolation` and zero raw sockets; external desync measurement is
  the operator's responsibility under authorization.
- HTTPS verifies SNI/hostname (no skip); self-signed lab TLS without a valid
  chain fails closed (no finding, scan continues).
- HTTP/2 negotiated via ALPN -> skip (smuggling invalid over h2); probe forces
  `http/1.1` ALPN and never downgrades.
- Single stable control pair (N=1 per axis), not statistical N=3: justified as
  a deterministic paired comparison, but high-jitter paths could still
  mislead; the 500 ms delta floor is the only stability anchor.
- Payloads are harmless terminators/markers only; cache-poisoning/DOS impact
  none by construction (<=10 requests, 5 s cap, benign follow-up GET).
