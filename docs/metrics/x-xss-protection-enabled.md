# Metrics: x-xss-protection-enabled

## Overview
Detects the legacy X-XSS-Protection filter enabled, which can introduce side-channel and content-injection risks.

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
- Dataset hash: `6cb0cb7ab857bbf37c65c632daf00cd1aaf742574ae2317fd5e2c426725001e9`
