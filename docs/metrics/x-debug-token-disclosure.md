# Metrics: x-debug-token-disclosure

## Overview
Detects an X-Debug-Token response header used by Symfony profiler debug tooling.

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
- Dataset hash: `23bb66ab4045d40c0febe29709e138d4ca8643188dbea193c8499bf3581d836e`
