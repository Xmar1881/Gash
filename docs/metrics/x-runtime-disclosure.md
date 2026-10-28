# Metrics: x-runtime-disclosure

## Overview
Detects an X-Runtime response header exposing per-request execution timing.

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
- Dataset hash: `2af5bd8434dde2116fa9c67d36f8bd4d6e2a6be17a648af9d141d6452e09756c`
