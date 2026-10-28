# Metrics: csp-form-action-missing

## Overview
Detects an existing Content-Security-Policy that omits form-action, allowing form submissions to any origin.

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
- Dataset hash: `7e06b03e0996606a4c3a5c4a20bdb203d75da4d90519d8481d407bb18fd8d0b1`
