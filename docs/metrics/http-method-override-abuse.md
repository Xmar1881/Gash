# Metrics: http-method-override-abuse

## Overview

Tier 1 plugin.

## Evidence Standard

GASH detector http-method-override-abuse.

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

- Dataset hash: `d44a2a813e9556df80240c0ffa0d3aa7d3905b94e207ddf320605fc5561dc953`
  (sha256 over all 4 fixture files).
- Samples: TP=2, FP=0, TN=2, FN=0.

## Limitations

- Firm ceiling where applicable.
