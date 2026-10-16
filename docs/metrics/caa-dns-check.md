<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/caa-dns-check.md
What: Unit-test report for the proto CAA check (GASH-027).
Why: Proves resolver-dependent CAA grading stays silent on ambiguity (no FP).
-->

# Metrics: caa-dns-check (proto, GASH-027)

## Overview

Engine proto recon (`engine.runProtoRecon`, `dns` detector, safe-profile).
`internal/proto/caa.go` issues a read-only TypeCAA query via pinned
`miekg/dns v1.1.73` (5 s cap, AXFR yok). Rule GASH-027 (CWE-295):
missing CAA → medium/`firm`; malformed CAA → medium/`firm`;
healthy, IP-literal, nil → silent. NXDOMAIN/timeout/SERVFAIL return an
error the engine treats as silent (no finding, no FP). Confidence ceiling
is `firm` (resolver-dependent, GASH-025 discipline); `confirmed` never fires.

## Evidence Standard

Finding carries `host`, `caa` (≤300 chars summary), `signal`
(`missing-caa`/`malformed-caa`), `detail`. Malformed validation is
intentionally narrow: empty tag, tag charset outside `[a-z0-9]`, empty
value, `iodef` without `mailto:`/`http(s):` scheme. Unknown tags and flag
bits never fire (forward-compatible, no FP).

## Unit Cases (no fixtures; no external DNS)

- Missing (injected empty): 1 `missing-caa` finding, medium/`firm`, GASH-027.
- Healthy (injected issue/issuewild/iodef): silent.
- Malformed ×4 (empty-tag, bad-tag, empty-value, bad-iodef): 1
  `malformed-caa` finding each, medium/`firm`.
- Loopback wire (`miekg/dns` server on 127.0.0.1): healthy → silent;
  NODATA → `missing-caa`; NXDOMAIN → error, silent.
- Timeout (loopback UDP blackhole, 300 ms): error, silent, well under the 5 s cap.
- Scope/IP/nil: deny → error; empty host → error; IP-literal → silent; nil → silent.
- Command: `go test ./internal/proto/ -run 'CAA|CAATimeout' -v` (no external query).

## Corpus Result

Proto CAA never reads HTTP bodies; corpus `firm` plus findings: 0 by
construction.

## Lab Result

Hermetic lab is the loopback wire test above (real CAA wire encode/parse
against 127.0.0.1, no external resolver). No real-target recall is claimed.

## Precision

Unit true positives 6 (1 missing + 4 malformed + 1 wire NODATA), false
positives 0. Precision 1.00 (unit-scoped, not real-target recall).

## Recall

Unit true positives 6, false negatives 0. Recall 1.00 (unit-scoped).

## Gate Verdict

PASS (unit-scoped). Engine proto recon has no plugin ID or fixtures, so
`TestMetricGate` does not apply; the gate is `go test ./...` plus
`go vet ./...`, both green.

## Limitations

- Resolver-dependent: same name can answer differently per resolver/view;
  ceiling stays `firm`.
- Default server is `/etc/resolv.conf` first entry, else `8.8.8.8:53`
  (override via `GASH_DNS_SERVER` or `Options.CAAServer`); enterprise
  split-horizon views may differ from public answers.
- CNAME handling relies on the recursive resolver; a bare-CNAME answer
  with no CAA records grades as missing.
- Narrow malformed rule means subtly-wrong-but-parseable policies
  (e.g. over-broad `issue` value) grade as healthy — deliberate FP caution.

## Dataset

No fixtures. Hermetic unit tests only (injected `LookupCAA` plus loopback
`miekg/dns` server and UDP blackhole). Re-run the command above; any
behaviour change must update this report, never imply real-target recall.
