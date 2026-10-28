# Metrics: cgit-version-disclosure

## Overview
Detects cgit version footers or cgit stylesheet markers; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled cgit instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `8eb08216d10c8e03cbce8598fb73d1fb4ac1af4e03a3513f3296a8a6b2d4798f`
