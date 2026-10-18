# Metrics: source-map-exposure

## Overview

Tier 1 plugin (GASH-066, CWE-540). Fixed bundle path list probed with GET;
each path triggering an envelope match pays one soft-404 control request.

## Evidence Standard

Firm ceiling. Accept requires the source map envelope (`"version":3` plus
`sources`/`mappings`/`names`/`sourcesContent`) in the 200 body; the same
envelope must be absent from the soft-404 control of the same path. SPA
catch-alls and version-only JSON (`{"version":3,"status":"ok"}`) stay clean.

## Fixtures

- Positive: 2 of 2 accepted (webpack map with sourcesContent, esbuild map),
  both firm.
- Negative: 3 of 3 rejected (SPA catch-all HTML, version-only JSON, WAF).

## Corpus Result

No unexpected firm plus; the envelope signature is not reachable from clean
bodies.

## Lab Result

Pending manual run against a lab serving unminified bundle maps.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate.

## Dataset

- Dataset hash: `3fe3fed5008b4d67eba7083ca6d1077ed4679d33d9699c77416f55c919869ad1`
  (sha256 over all 5 fixture files).
- Samples: TP=2, FP=0, TN=3, FN=0.

## Limitations

- Firm ceiling: single-channel content observation, never confirmed.
- Hashed bundle filenames (`main.a1b2c3.js.map`) are only reachable when the
  build emits the unhashed alias names in the fixed list; no crawling.
- Source maps referenced only via `//# sourceMappingURL` comments in fetched
  JS are out of scope for this standalone screen.
