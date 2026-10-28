# Metrics: x-rack-cache-disclosure

## Overview
Detects an X-Rack-Cache response header exposing Rails cache behavior.

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
- Dataset hash: `f96bcf2290d24690befe3c25c444f2ca1e1db008438ea580e699728b4bb0737e`
