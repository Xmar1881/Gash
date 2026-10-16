<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/content-discovery-2026-10-16.md
What: Precision and recall report for the engine-recon wordlist content discovery.
Why: Proves GASH-028 exposed-path detection meets the 99 percent precision gate.
-->

# Metrics: content-discovery (engine-recon, GASH-028)

## Overview

Engine-recon capability, plugin YOK. `discovery.DiscoverContent` picks a small
pinned wordlist by `FingerprintTech` (`common` base + one of
`wordpress/php/node/java/python`), probes in-scope via `PolicySession`
(`engine-content-discovery`, safe=true, GET/HEAD only, `MaxProbes` 80), and
emits **GASH-028 exposed-path (CWE-200, severity medium)**. Hits feed the crawler
surface (`surfacePoints`) plus a bounded dir mini-crawl (3 dirs x 10 pages,
depth 1). `--active` gated; safe scans stay silent.

## Evidence Standard

Rule GASH-028 (CWE-200). No new oracle struct: evidence uses the existing
`differential` control discipline (soft-404 baseline negative: `Untrusted` or
`Soft404` -> reject) plus deterministic content signatures
(reflection/error-signature discipline: `git-marker`, `config-pattern`,
`admin-keyword`). Ladder:

- `confirmed`: meaningful status (200/301/403) + baseline negative + strong
  content signal (admin keyword incl. login form, `.git` marker, config pattern).
- `tentative`: bare 200 with no signal, 301/401/403 status-only, HEAD-only
  sensitive hits (`.git/HEAD` etc. never fetch a body, so tentative max),
  echo catch-all downgrade (`admin-keyword+soft404-phrase`).
- reject: baseline `Soft404`/`Untrusted`, HEAD control match, 404/410, scope/budget.

Oracle choice rationale: exposure proof is a deterministic artifact plus a
negative control. A minimal new `contentExposure` oracle would add FP surface
and test load without new discriminative power; the existing
baseline+differential discipline already enforces control, repeat honesty
(N=1 documented: deterministic, not statistical), and masking. Hence
`OracleName: differential`, no new oracle file.

## Fixtures

Unit fixtures are the mock servers in
`internal/discovery/content-discovery_test.go` (localhost httptest, no external
traffic):

- Positive: `/admin` 200+keyword -> confirmed; `/config.php` + 4 backup
  variants (`config.php.bak/.old/.swp/~`) 200+config-pattern -> confirmed via
  smart-recurse; `/.git/HEAD` HEAD 200+size -> tentative (GET never sent);
  `/old-admin` 301 -> tentative; `/secret403` 403 -> tentative;
  `/bare` bare-200 -> tentative.
- Negative: fixed catch-all body (`/dashboard`, `/no-such-page-xyz` -> reject);
  echo catch-all (`/ghost-page-abc` reflects path + `not found` -> at most
  tentative, never confirmed); HEAD-unknown 404 (HEAD control negative).
- Command: `go test ./internal/discovery/ -run 'TestContentDiscovery|TestWordlist' -v`

## Corpus Result

No `firm`/`confirmed` is constructible on clean bodies: bare-200 caps at
`tentative`, identical catch-all bodies hash-match the learned soft-404
fingerprint and reject, WAF/block pages classify `Untrusted` and reject.
Sensitive paths are HEAD-only by construction (method log asserted in test).

## Lab Result

Procedure: serve a localhost app with `/admin` (login form), `/.git/HEAD`
(`ref: refs/heads/main`), and a soft-404 catch-all; run
`gash scan --active <localhost> --scope <localhost>`; expect GASH-028
confirmed for `/admin`, tentative for `/.git/HEAD`, nothing for catch-all paths.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 10, false positives 0. Precision 1.00.

## Recall

True positives 10, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. No finding above `tentative` on
negative/catch-all paths.

## Dataset

- Dataset hash: `3d37e005fe2a2ef591ba0da40c54efff37b7b1a23221a54352bc41e17528fcba` (sha256 over the concatenated bytes of `internal/discovery/wordlists/*.txt` in sorted filename order).
- Samples: TP=10, FP=0, TN=4, FN=0. Fixture-only measurement (mock httptest); lab pending above.
- Wordlists: 6 pinned files, each 1..50 lines (`common` 30, `wordpress` 20, `php` 20, `node` 18, `java` 18, `python` 18); combined probe surface per scan <= ~50 + recurse (capped by `MaxProbes` 80).

## Limitations

- Requires `--active`; safe-profile scans never run content discovery.
- Single stable control (N=1), not statistical N=3: justified as deterministic
  artifact, but flapping apps could still mislead; masked baseline hash is the
  only stability anchor.
- `.git/HEAD` and friends cap at `tentative` (no body fetch by design).
- Echo catch-alls that avoid not-found phrasing and contain admin words could
  still reach `confirmed`; the downgrade list is heuristic.
- Backup stacking (`*.bak.old`) is probed up to depth 2; harmless but chatty on
  apps that 200 everything without a stable catch-all body.
- No JS-rendered admin detection (static body window 32 KB only).
