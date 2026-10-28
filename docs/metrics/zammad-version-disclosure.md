# Metrics: zammad-version-disclosure

## Overview
Detects Zammad markers or client asset paths; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Zammad instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `fb0c8c9c050580f2065c19c38fc6b1e4574a800eff8ad0d8840b00bdfda2e0c6`
