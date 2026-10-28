# Metrics: coep-unsafe-none

## Overview
Detects an explicit Cross-Origin-Embedder-Policy unsafe-none that disables embedder isolation.

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
- Dataset hash: `63edbf9e22acf5d8c4593a97239a2ae1f461f20691853d40b7597347e6d42b1c`
