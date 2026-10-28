# Metrics: opensearch-version-disclosure

## Overview
Detects the OpenSearch distribution field on the public root API; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled OpenSearch instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `44c0b639e8e443665560b14fb1c3678c60126ca407eb8b243467f2ae2e316877`
