# Metrics: redis-commander-version-disclosure

## Overview
Detects Redis Commander markers on the admin UI; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Redis Commander instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `24addffa512b5fc002457cd7656d3f72c7a32351bc6b91641a2d0adf45e50642`
