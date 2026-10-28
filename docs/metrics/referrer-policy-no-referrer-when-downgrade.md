# Metrics: referrer-policy-no-referrer-when-downgrade

## Overview
Detects the legacy no-referrer-when-downgrade Referrer-Policy, which sends full URLs on same-scheme requests.

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
- Dataset hash: `92b140e0fc3472440963b87bce71d54ce5c1c746c2c9ac7ff440411625fd4f41`
