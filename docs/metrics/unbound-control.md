# Metrics: unbound-control

## Overview

Tier 1 discovery plugin for a product-specific management or metadata exposure.
The detector uses a bounded GET path and a narrow response marker; it never
executes code and caps the result at firm confidence.

## Fixtures

- Positive: 1 of 1 accepted (firm).
- Negative: 1 of 1 rejected.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00 on the fixture corpus.

## Corpus

The positive fixture contains the product marker. The negative fixture is an
ordinary application response without control-plane markers.

## Lab

Status: pending manual run. No external target is contacted by this report.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 fixture gate.

## Dataset

- Dataset hash: `aa6dd3bce3ac4c51fa9737ad1bf43571278a9052cf6d1246cb405c3ae436c69d`
- Samples: TP=1, FP=0, TN=1, FN=0.
