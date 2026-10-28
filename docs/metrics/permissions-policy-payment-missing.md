# Metrics: permissions-policy-payment-missing

## Overview
Detects an existing Permissions-Policy that does not restrict the Payment Request API.

## Corpus
Precision 1.00; fixture cases cover the policy violation, the compliant header set, and the absent-header case owned by the presence check.

## Lab
Pending manual run against a controlled endpoint; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `9e5096ca25c4736ebaf629429b41545c8afd4d16912059ceb8f2bda2bcf6f16b`
