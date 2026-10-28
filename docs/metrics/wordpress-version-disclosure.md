# Metrics: wordpress-version-disclosure

## Overview
Detects WordPress asset paths (wp-content themes/plugins or wp-includes) in public responses; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled WordPress instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `2c6da90ad2553244504f29bfd364aa049f7b705be1369924ed40639069ab454b`
