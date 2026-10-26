<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/ssrf-json-body-oob.md
What: Precision and recall report for the Tier 2 JSON-body blind SSRF plugin.
Why: Proves per-field JSON OOB payloads meet the 99 percent precision gate and
  skip honestly without an OOB server.
-->

# Metrics: ssrf-json-body-oob

## Overview

Tier 2 active JS plugin. Oracle `oob` (`oob: required`). A JSON API field that
holds a URL (avatar, webhook, import source) is fetched server-side, but Tier 1
cannot rebuild a JSON object around a discovered field.

Each field gets its own single-use callback token, so an incoming callback can
only confirm the exact request that caused it. One shared bounded window
(`oobAny`, 10 s / 2 polls) covers the whole corpus.

## Evidence Standard

OOB rule (GASH-008/012/013 family extended to JSON APIs). `confirmed` requires
a matched callback token; without a configured server the plugin returns no
candidates (the scheduler also skips it as `tier3`-independent
`oob-not-configured`). No tentative noise is ever emitted.

## Fixtures

- Positive: 1 of 1 accepted (`confirmed`; callback observed for the injected
  field).
- Negative: 1 of 1 rejected (no callback).
- Command:
  `go run ./cmd/gash plugins test plugins/ssrf/ssrf-json-body-oob.js`

## JS E2E

`TestSSRFJSONBodyOOBE2E` (`tests/plugins/tier2_json_sinks_test.go`) executes
the real script through `loader.ExecuteJS` with a mocked transport:

- OOB enabled plus a matching callback: one `confirmed` candidate; the request
  is asserted to carry the callback URL inside the JSON body with an
  `application/json` content type.
- OOB disabled (`host.oob.generate` returns null): zero candidates and no
  request is sent.
- Send budget stays under the declared `max_requests`.

No new `host.oracles.*` binding is introduced (source grep asserts only
`host.oob.generate` plus `host.oracles.oobAny`).

## Corpus Result

Oracle `oob` is callback-gated: the shared corpus gate runs the negative OOB
fixture with the mock enabled, so a missing callback rejects and no `firm`-plus
finding can be produced.

## Lab Result

Procedure: serve a JSON API endpoint that fetches a field value in the
localhost lab, point `--oob-server` at the self-hosted callback server, scan
with `--active`, expect one high severity finding at `confirmed`.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `f8908e54664821e153c50d3a4cec0232de4b66bdae9ae9c13adc4d94a99fe31e`
  (sha256 over both fixture files under `tests/fixtures/ssrf-json-body-oob/`).
- Samples: TP=1, FP=0, TN=1, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Only the discovered field is sent; sibling fields are not replayed.
- Numeric-notation hosts and redirect-chain variants carry the token only in
  the path (see `docs/known-limits.md`); those live in `ssrf-blind-oob`.
- Cloud-metadata targets are deliberately out of scope here.
