# Metrics: permissions-policy-microphone-missing

## Overview
Detects an existing Permissions-Policy that does not restrict microphone access.

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
- Dataset hash: `7a64487accb29aa20212d811a5e85723b13bf7b5b0a014801aabe540ad306453`
