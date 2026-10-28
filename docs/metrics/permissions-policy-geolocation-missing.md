# Metrics: permissions-policy-geolocation-missing

## Overview
Detects an existing Permissions-Policy that does not restrict geolocation access.

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
- Dataset hash: `e97d46eeb14e0589df38a2ce1a5e4fc02cde48b7e24fe45a02e35a8009d33900`
