# Metrics: file-inclusion-rfi

## Overview

Tier 1 reflection screen. This is a legacy RFI check that shares the
`reflection` oracle with `rfi-remote-include`; it does not prove remote
inclusion or execution. The live ceiling is `tentative`
(`require_executable_context: true`).

## Evidence Standard

GASH detector `file-inclusion-rfi`. A loopback URL canary must be reflected in
an allowed context (`html-text`, `attr`, or `url`) with a distinguishable
control. HTML text and ordinary URL/attribute reflection are not inclusion
proof, so they are capped at `tentative`. Comments, non-executable reflections,
and controls that contain the same canary are rejected.

## Fixtures

- Positive: 2 of 2 accepted (`tentative`).
- Negative: 2 of 2 rejected.
- Command: `go run ./cmd/gash plugins test plugins/file-inclusion-rfi/file-inclusion-rfi.yaml`

## Corpus Result

No unexpected `firm` plus. The reflection oracle corpus includes clean, SPA,
WAF, encoded, and dynamic bodies; the loopback canary is absent from those
bodies.

## Lab Result

2026-10-20 native DVWA: the screen produced `tentative` loopback-URL reflection
findings on `/vulnerabilities/fi` even though DVWA has `allow_url_include=Off`.
This confirms the intended ceiling: the finding is a reflection screen, not
evidence of remote inclusion. It is declared unscored in `native-lab.yaml` and
is not counted as TP or FP in the native-lab benchmark.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate.

## Dataset

- Dataset hash: `21068f5faac1effa8465039c0eb23e336daa22bc2e67c61be0b7680cf6e991b4`
  (sha256 over all 4 fixture files).
- Samples: TP=2, FP=0, TN=2, FN=0.

## Limitations

- Reflection only; no remote fetch, include, or execution proof.
- Backend include semantics (for example PHP `allow_url_include=Off`) are not
  fingerprinted, so a tentative reflection can occur on a host that cannot
  include remote content.
- Duplicate of the `rfi-remote-include` screen; both are unscored in the
  native-lab dataset.
