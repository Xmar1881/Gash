# Metrics: csp-upgrade-insecure-requests-missing

## Overview
Detects an existing Content-Security-Policy that omits upgrade-insecure-requests, leaving mixed-content fetches possible.

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
- Dataset hash: `6d3ecea54865a00315bb6cac38d1ae01ffd310d1ca4b757829f484409e306f66`
