# Metrics: meilisearch-version-disclosure

## Overview
Detects the Meilisearch pkgVersion field on the public version API; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Meilisearch instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `d4ee45487559e90d0cdeeb2f74b2631d695ce24b44f4cb63b84689c285c4103b`
