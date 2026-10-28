# Metrics: csp-base-uri-missing

## Overview
Detects an existing Content-Security-Policy that omits base-uri, leaving relative URL resolution unconstrained.

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
- Dataset hash: `44ee75c5005e2fa417db10cf800186805b563697147526f4a03f4795cfaf31aa`
