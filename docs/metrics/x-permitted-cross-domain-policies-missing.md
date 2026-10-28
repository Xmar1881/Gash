# Metrics: x-permitted-cross-domain-policies-missing

## Overview
Detects a missing X-Permitted-Cross-Domain-Policies header that lets legacy Adobe clients load cross-domain policy files.

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
- Dataset hash: `7dfbfb70fc77ccd45cb0dc218f3afa795156d308fae2e4392d1287330473d675`
