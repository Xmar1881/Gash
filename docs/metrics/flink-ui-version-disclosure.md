# Metrics: flink-ui-version-disclosure

## Overview
Detects Apache Flink dashboard markers; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Flink UI instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `1f400138949061291039804b2efd5a66e4ae342c0cc9ffed5dcf8bedc836460f`
