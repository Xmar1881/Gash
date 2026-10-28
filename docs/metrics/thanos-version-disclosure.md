# Metrics: thanos-version-disclosure

## Overview
Detects the Thanos buildUser field on the public buildinfo API; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Thanos instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `97d932747e1b7437268d471bd8791661754e2a9f01765d8b1bc30d9c9ea9b16e`
