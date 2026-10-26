<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/insecure-deserialization-json-body.md
What: Precision and recall report for the Tier 2 JSON-body deserialization plugin.
Why: Proves the deserialization signature family applied to JSON fields meets
  the 99 percent precision gate at its honest firm ceiling.
-->

# Metrics: insecure-deserialization-json-body

## Overview

Tier 2 active JS plugin. Oracle `error` with `mode: deserialization`, declared
once in the frontmatter `oracle_params` block. A JSON API field that is
base64-decoded and handed to a native deserializer (Java ObjectInputStream, PHP
unserialize, Python pickle, .NET BinaryFormatter) is unreachable from the
query-point plugin.

Every payload is paired with a neutral-value request on the same field. The
payloads are inert serialization markers, never a gadget chain, so the ceiling
stays `firm`: the finding is a deserialization error signature, not code
execution.

## Evidence Standard

Error-signature rule (GASH-029 family extended to JSON bodies). Control
discipline: a signature that also appears for the neutral value rejects.

## Fixtures

- Positive: 2 of 2 accepted (`firm`; Java InvalidClassException and PHP
  unserialize notice).
- Negative: 2 of 2 rejected (signature also present for the control; opaque
  field).
- Command:
  `go run ./cmd/gash plugins test plugins/deserialization/insecure-deserialization-json-body.js`

## JS E2E

`TestInsecureDeserializationJSONBodyE2E` (`tests/plugins/tier2_batch_test.go`)
executes the real script through `loader.ExecuteJS`: a backend erroring only for
the Java marker yields one `firm` candidate with the JSON content type and the
escaped payload asserted; a control that always errors yields none.

## Corpus Result

Oracle `error` evaluated against clean, SPA, WAF, encoded, and dynamic bodies in
the shared corpus gate: no corpus body carries a deserialization signature.

## Lab Result

Procedure: serve a JSON import endpoint that deserializes a field in the
localhost lab, scan with `--active`, expect one high severity finding at `firm`.
Status: pending manual run.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `1519ab2dccacbd5ba81f3c623658baf79be257402600a8696e6ca5ef5bb05963`
  (sha256 over all 4 fixture files under
  `tests/fixtures/insecure-deserialization-json-body/`).
- Samples: TP=2, FP=0, TN=2, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- Signature-only: no gadget chain is sent and no RCE is claimed (firm ceiling).
- .NET ViewState and JSON.NET type handling are not modelled beyond the marker.
- Base64 decoding of the field is assumed; a double-encoded field can miss.
