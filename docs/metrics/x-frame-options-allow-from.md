# Metrics: x-frame-options-allow-from

## Overview
Detects the obsolete X-Frame-Options ALLOW-FROM directive that modern browsers ignore.

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
- Dataset hash: `e8a0483aa16d69487ee8e62aa87c0545e45429a5f31a99c2fc7e88cc69074ebc`
