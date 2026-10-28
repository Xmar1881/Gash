# Metrics: hsts-preload-missing

## Overview
Detects an existing Strict-Transport-Security policy that omits the preload directive.

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
- Dataset hash: `cee52f79cf107df7a63c9dc85ca9c76895d4464b9dc613bb90ef44b35c24f25e`
