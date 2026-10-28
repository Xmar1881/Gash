# Metrics: coop-unsafe-none

## Overview
Detects an explicit Cross-Origin-Opener-Policy unsafe-none that disables cross-origin isolation.

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
- Dataset hash: `38421f94d892663d188e5ef8cce439ecf3a40cdbe72013b305467d9cf99042fa`
