# Metrics: jira-version-disclosure

## Overview
Detects the Jira serverInfo response marker; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Jira instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `4ecc34d72faa324756fa21207b31a728e3b1504b2170c354e7c2a1c3dbd79957`
