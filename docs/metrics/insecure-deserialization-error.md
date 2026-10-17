<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/insecure-deserialization-error.md
What: Precision and recall report for the insecure deserialization error-based reference plugin.
Why: Proves Tier 1 error oracle (deserialization mode) meets signature-plus-control standard
  for Java/Python/PHP unmarshal errors at the firm ceiling with no gadget chain.
-->

# Metrics: insecure-deserialization-error

## Overview

Tier 1 active plugin. Oracle `error` with `mode: deserialization` and
`signature_set: ["deserialization"]` (GASH-029, CWE-502). Java
(`InvalidClassException`, `ObjectInputStream.readObject`), Python
(`UnpicklingError`, `pickle.loads`), and PHP (`unserialize()`, `__wakeup`,
`__destruct`) parse-error signatures plus absent-in-control proof. Maximum
confidence `firm` with or without control: an error string alone never proves
remote code execution. Probe payload is a malformed serialization header
fragment (`rO0ABkdBU0hfUFJPQkU`); no gadget, no class descriptor, no RCE chain
is ever sent.

## Evidence Standard

GASH-029 extends the GASH-004 error-signature family. Accept requires a
deserialization-specific signature in the probe body plus absence of the same
signature in the neutral control. WAF/block pages classify `Untrusted` and
always reject. Firm ceiling is intentional: a parse error proves attacker-
reachable unmarshal code, not exploitability. Blind deserialization
(Log4Shell-style, GASH-013) stays OOB-required and out of scope.

## Fixtures

- Positive: 2 of 2 accepted (2 `firm` with control; Java `InvalidClassException`, Python `UnpicklingError`).
- Negative: 2 of 2 rejected (no error, same error in control).
- Command: `go run ./cmd/gash plugins test plugins/deserialization/insecure-deserialization-error.yaml`

## Corpus Result

Oracle `error` (deserialization mode) evaluated against clean, SPA, WAF,
encoded, and dynamic bodies. `firm` plus findings: 0. Covered by
`TestDeserializationSignature` in `internal/oracle/new_detectors_test.go`.

## Lab Result

Procedure: serve a lab endpoint that unmarshals the `data`/`payload` parameter
(PHP `unserialize`, Java `readObject`, or Python `pickle.loads`) and renders
errors, scan with `--active --scope <lab>` on the aggressive profile, expect
one high severity finding at `firm` and no claim on the hardened control.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `ce288b85534e1dab0805e2c6d8a1be2526d4baedc67babb5046e2b7d7e2b3af2`
  (sha256 over all 4 fixture files under `tests/fixtures/insecure-deserialization-error/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Parse-error strings cannot prove exploitability; triage must confirm a gadget path before claiming RCE.
- Blind deserialization without error output is out of scope (GASH-013, OOB-required).
- The probe is one malformed header fragment; format-specific (ViewState, Node `node-serialize`) variants are future work.
