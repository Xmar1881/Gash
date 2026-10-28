# Metrics: gitlab-version-disclosure

## Overview
Detects GitLab markers on public login pages; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled GitLab instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `3a0f9a7ff0579dd46d578b8f0f8f8b2f550f78a2c2375b0e9c7ed75844f22c37`
