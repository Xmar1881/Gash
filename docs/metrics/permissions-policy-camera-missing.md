# Metrics: permissions-policy-camera-missing

## Overview
Detects an existing Permissions-Policy that does not restrict camera access.

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
- Dataset hash: `e62a8df887c7fbffb2705c18edeb9ef6b4b06734fd78ecf4607cbe9e8d9513a7`
