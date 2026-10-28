# Metrics: storm-ui-version-disclosure

## Overview
Detects Storm UI markers or cluster-summary API paths; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Storm UI instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `8654bd357175f78ff0e0cc180c9de09d644f0d4e6844951796151703018c065d`
