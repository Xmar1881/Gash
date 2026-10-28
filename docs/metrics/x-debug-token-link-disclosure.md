# Metrics: x-debug-token-link-disclosure

## Overview
Detects an X-Debug-Token-Link response header pointing at a profiler endpoint.

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
- Dataset hash: `42d8c17f1965d223471a48583cf7fd5133269dbe1c0d5f00a52a1aa736e807a2`
