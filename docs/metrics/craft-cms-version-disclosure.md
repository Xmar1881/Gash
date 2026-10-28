# Metrics: craft-cms-version-disclosure

## Overview
Detects Craft CMS response headers or body markers; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Craft CMS instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `d1a7b70ea781fb48dc7d2e658493788da0ece08737f835b1a566620921e67a9c`
