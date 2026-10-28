# Metrics: csp-default-src-missing

## Overview
Detects an existing Content-Security-Policy that omits the default-src fallback directive, leaving unlisted fetch directives unrestricted.

## Corpus
Precision 1.00; fixture cases cover a policy without default-src, a policy with default-src, and an absent header owned by the presence check.

## Lab
Pending manual run against a controlled endpoint; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `9b0910d38e5a0fc455db2df03f77cda5e60b67b742ac42467af43acd1f8049e4`
