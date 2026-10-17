# Metrics: cache-poisoning-host-header

## Overview

Tier 1 plugin.

## Evidence Standard

GASH detector cache-poisoning-host-header.

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

- Dataset hash: `59405b67742505d40c41079c2da0e804b74c00e228ed5bc7ebc1d0e2003616d6`
  (sha256 over all 4 fixture files).
- Samples: TP=2, FP=0, TN=2, FN=0.

## Limitations

- Firm ceiling where applicable.
