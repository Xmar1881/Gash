# Metrics: jsonp-callback-injection

## Overview

Tier 1 plugin (GASH-062, CWE-79). Deterministic canary `gash_jsonp_9c1f7e2a`
sent through `callback`, `cb`, `jsonp`, and `jsoncallback`.

## Evidence Standard

Firm ceiling. Accept requires the canary in HTML text context (the classic
`callback({...})` body) or in executable script context (canary used as a
script identifier/call). Pure JSON documents, JavaScript string reflections,
HTML comments, encoded output, and WAF blocks are rejected.

## Fixtures

- Positive: 2 of 2 accepted (bare JSONP wrapper body, script-wrapped
  callback), both firm.
- Negative: 4 of 4 rejected (strict JSON with echoed callback, callback
  inside a JS string literal, HTML comment reflection, WAF).

## Corpus Result

No unexpected firm plus; the canary is distinctive and never appears in the
clean corpus.

## Lab Result

Pending manual run against a JSONP demo endpoint.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate.

## Dataset

- Dataset hash: `5487e595833ad5debbcadb25183e0ee3b5a9a65412ab04b70d2c35ea0a957f3a`
  (sha256 over all 6 fixture files).
- Samples: TP=2, FP=0, TN=4, FN=0.

## Limitations

- Firm ceiling; the oracle does not inspect `(` framing or Content-Type, so
  the claim is "callback value reflected", not script execution.
- Callback parameter names beyond the fixed list are missed by design.
