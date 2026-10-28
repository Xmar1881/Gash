# Metrics: confluence-version-disclosure

## Overview
Detects the Confluence ajs-version-number metadata field; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Confluence instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `007189cb969e5c22956b466c15bb88693d62452c498e3bab317e100660a36393`
