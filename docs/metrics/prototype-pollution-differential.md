# Metrics: prototype-pollution-differential

## Overview

Tier 1 active plugin. Oracle `differential` with firm ceiling.

## Evidence Standard

GASH-040 (CWE-1321).

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

- Dataset hash: `70d5674983145ca626a0c4523916036ca4215a201617ea6045d8f3afbd41fd82`
  (sha256 over all 4 fixture files).
- Samples: TP=2, FP=0, TN=2, FN=0.

## Limitations

- Firm ceiling (no confirmed).
