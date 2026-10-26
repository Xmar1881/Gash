<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/command-injection-json-body-oob.md
What: Precision and recall report for the Tier 2 JSON-body blind command injection plugin.
Why: Proves per-field JSON shell payloads meet the 99 percent precision gate and
  skip honestly without an OOB server.
-->

# Metrics: command-injection-json-body-oob

## Overview

Tier 2 active JS plugin. Oracle `oob` (`oob: required`). JSON fields such as
filename, format, target and source are routinely passed to media converters
and shell helpers, but Tier 1 cannot rebuild a JSON object around a discovered
field.

Seven shell variants per field (command separators, pipe, backticks, `curl`,
`wget`, `nslookup`) each carry their own single-use callback token, so an
incoming callback can only confirm the exact request that caused it. One shared
bounded window (`oobAny`, 10 s / 2 polls) covers the whole corpus.

## Evidence Standard

OOB rule (GASH-010 family extended to JSON APIs). `confirmed` requires a
matched callback token; there is no timing fallback and no tentative noise.
Without a configured server the plugin returns no candidates and sends nothing.

## Fixtures

- Positive: 1 of 1 accepted (`confirmed`; callback observed for the injected
  field).
- Negative: 1 of 1 rejected (no callback).
- Command:
  `go run ./cmd/gash plugins test plugins/command-injection/command-injection-json-body-oob.js`

## JS E2E

`TestCommandInjectionJSONBodyOOBE2E`
(`tests/plugins/tier2_json_stored_oob_test.go`) executes the real script through
`loader.ExecuteJS` with a mocked transport:

- OOB enabled plus a matching callback: one `confirmed` candidate; the request
  is asserted to carry the callback URL or domain inside an `application/json`
  body, and all variants stay inside the budget.
- OOB disabled (`host.oob.generate` returns null): zero candidates and zero
  requests.
- Send budget stays under the declared `max_requests`.

No new `host.oracles.*` binding is introduced (source grep asserts only
`host.oob.generate` plus `host.oracles.oobAny`).

## Corpus Result

Oracle `oob` is callback-gated: the shared corpus gate runs the negative OOB
fixture with the mock enabled, so a missing callback rejects and no `firm`-plus
finding can be produced.

## Lab Result

Procedure: serve a JSON API endpoint that passes a field into a shell command
in the localhost lab, point `--oob-server` at the self-hosted callback server,
scan with `--active`, expect one critical severity finding at `confirmed`.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `a48fe8a2b454f516a427b6104801d974b8d8439f13b6d1d9ebd9939bf6332581`
  (sha256 over both fixture files under
  `tests/fixtures/command-injection-json-body-oob/`).
- Samples: TP=1, FP=0, TN=1, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Only the discovered field is sent; sibling fields are not replayed.
- Windows-specific separators (`&`, `&&`) are not in the v1 corpus.
- Egress-filtered targets produce no callback and therefore no finding
  (false negative by design, never a fabricated one).
