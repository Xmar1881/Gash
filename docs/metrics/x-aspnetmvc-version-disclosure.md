# Metrics: x-aspnetmvc-version-disclosure

## Overview
Detects the X-AspNetMvc-Version response header exposing the ASP.NET MVC version.

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
- Dataset hash: `3a55ed5f7d0b3ab24d8f4e7e33292a8a06b0b13636303de5136c0e612e778b74`
