# Metrics: ssrf-internal-port-scan

## Overview

Tier 1 plugin.

## Evidence Standard

GASH detector ssrf-internal-port-scan.

## Fixtures

- Positive: 2 of 2 accepted.
- Negative: 2 of 2 rejected.

## Corpus Result

No unexpected firm plus.

## Lab Result

Pending manual run.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate.

## Dataset

- Dataset hash: `6b2f43a8a953489bba741abc9d081ea1dff7093ac78f7868e86821cdd44ff0f1`
  (sha256 over all 4 fixture files).
- Samples: TP=2, FP=0, TN=2, FN=0.

## Limitations

- Firm ceiling where applicable.
