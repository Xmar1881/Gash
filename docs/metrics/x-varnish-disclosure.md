# Metrics: x-varnish-disclosure

## Overview
Detects an X-Varnish response header exposing Varnish cache transaction IDs.

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
- Dataset hash: `ac17de83a592f6bd8acd3d6dec67f46c239a7f2f5e535fb70e394efc137bdd6d`
