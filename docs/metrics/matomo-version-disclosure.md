# Metrics: matomo-version-disclosure

## Overview
Detects Matomo markers or tracking script paths; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Matomo instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `6011cc66e27ae57e4772ada95bebf305b629c68019a37931611560921e0ef113`
