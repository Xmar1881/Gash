# Metrics: x-generator-disclosure

## Overview
Detects an X-Generator response header that fingerprints the CMS or site generator.

## Corpus
Precision 1.00; Fixture cases cover the policy violation, the compliant header set, and (for directive checks) the absent-header case.

## Lab
Pending manual run against a controlled endpoint; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `6c752b728957025b49d60ce6b602eaf5b69eaaba2242df6204dcb5c98b5fd995`
