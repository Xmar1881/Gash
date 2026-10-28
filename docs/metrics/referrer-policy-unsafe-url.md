# Metrics: referrer-policy-unsafe-url

## Overview
Detects a Referrer-Policy set to unsafe-url, which leaks full URLs to cross-origin destinations.

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
- Dataset hash: `788865b7556ce6440e430ec8c8f92af78b78d5c20cb4d7482fa855c5ad55e412`
