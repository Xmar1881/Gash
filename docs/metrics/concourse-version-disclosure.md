# Metrics: concourse-version-disclosure

## Overview
Detects the Concourse worker_version field on the public info API; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Concourse instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `e5997bfb46e70caf047047046f7bb66ed15c9b6f1290b9aba38957e664a5eea0`
