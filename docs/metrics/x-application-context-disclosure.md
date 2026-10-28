# Metrics: x-application-context-disclosure

## Overview
Detects a Spring Boot X-Application-Context header exposing the application name and active profile.

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
- Dataset hash: `01cce7220e4c43a15cbaa05a214cc161ac9f0e1764507f327875a771d438809d`
