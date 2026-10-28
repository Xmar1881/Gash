# Metrics: csp-require-trusted-types-missing

## Overview
Detects an existing Content-Security-Policy that omits require-trusted-types-for, leaving DOM sink hardening disabled.

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
- Dataset hash: `f875d4abce6de5c919cf3e20adc0cd5df0be0ce5d8a63bda2a52d4dc01cc40a7`
