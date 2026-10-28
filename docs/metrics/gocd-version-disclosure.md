# Metrics: gocd-version-disclosure

## Overview
Detects the GoCD build_number field on the public version API; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled GoCD instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `3e629032113f0bf2ab907169ad4f9676160a43f2ac7d439a9965bedd2b6ccabb`
