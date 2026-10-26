<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/lfi-json-body.md
What: Precision and recall report for the Tier 2 JSON-body path traversal plugin.
Why: Proves per-field JSON traversal payloads meet the 99 percent precision gate
  with real file-content signatures behind the error oracle.
-->

# Metrics: lfi-json-body

## Overview

Tier 2 active JS plugin. Oracle `error` with `mode: path_traversal`, declared
once in the frontmatter `oracle_params` block. Tier 1 path traversal injects
into query parameter names, so a JSON API field used as a file path is never
exercised; the payload has to be built into a JSON object and sent with an
explicit `application/json` content type.

Every payload is paired with a neutral-value request on the same field. Only
real file-content signatures (`root:x:0:0`, `[fonts]`) count; a stack trace or a
"no such file" message is not accepted by this mode.

## Evidence Standard

Error-signature rule (GASH-017 family extended to JSON APIs). The control must
not carry the signature, otherwise the page leaks it independently and the
finding rejects. WAF/untrusted baselines reject through the shared guard.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`; unix passwd content and windows ini
  content).
- Negative: 2 of 2 rejected (signature also in the control; sanitised path).
- Command: `go run ./cmd/gash plugins test plugins/path-traversal/lfi-json-body.js`

## JS E2E

`TestLFIJSONBodyE2E` (`tests/plugins/tier2_mode_ceiling_test.go`) executes
the real script through `loader.ExecuteJS`:

- Backend returning passwd content only for the traversal payload: one
  `confirmed` candidate; JSON content type and raw body asserted.
- Backend that never returns file content: zero candidates.
- The plugin must NOT pass a `mode` argument itself: the mode comes from
  `oracle_params` (source grep asserts this).
- Send budget stays under the declared `max_requests`.

No new `host.oracles.*` binding is introduced (source grep asserts only
`host.oracles.error`).

## Corpus Result

Oracle `error` evaluated against clean, SPA, WAF, encoded, and dynamic bodies
in the shared corpus gate. No corpus body carries a file-content signature, so
no `firm`-plus finding is produced.

## Lab Result

Procedure: serve a JSON API export endpoint whose handler joins a field into a
filesystem path in the localhost lab, scan with `--active`, expect one high
severity finding at `confirmed`.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `5127a1cc1d256a474d6bc4edc30c866f95b40ed5a7b66219f19ec50aa8eebcbc`
  (sha256 over all 4 fixture files under `tests/fixtures/lfi-json-body/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Only the discovered field is sent; sibling fields are not replayed.
- Absolute-path and wrapper payloads (`php://filter`) are not in the v1 corpus.
- Blind traversal without content reflection stays undetectable (documented as
  GASH-018 in `docs/known-limits.md`).
