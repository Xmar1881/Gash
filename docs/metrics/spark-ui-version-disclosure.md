# Metrics: spark-ui-version-disclosure

## Overview
Detects Spark Master/UI markers on the public dashboard; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Spark UI instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `ba8e4c92e69ad52efde10a79ec4d253ad42b530841da1b12bf6b620f10f6baa2`
