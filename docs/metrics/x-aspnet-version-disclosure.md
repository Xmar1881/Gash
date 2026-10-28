# Metrics: x-aspnet-version-disclosure

## Overview
Detects the X-AspNet-Version response header exposing the ASP.NET runtime version.

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
- Dataset hash: `85ac2b21321a5b3fd0a11db47d901259e8813e4b96854030587a38b5e8932ea3`
