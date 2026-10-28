# Metrics: feature-policy-deprecated

## Overview
Detects the deprecated Feature-Policy response header that is superseded by Permissions-Policy.

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
- Dataset hash: `d8b1873ee92a5cea67625b24a90b36ed2d59bef086d9872e99a60e9c9a4bdfc4`
