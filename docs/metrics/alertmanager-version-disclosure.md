# Metrics: alertmanager-version-disclosure

## Overview
Detects the Alertmanager versionInfo field on the public status API; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Alertmanager instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `d5e762a32993b43bc7863144d6dc142ad57fd94de0498b74befe99e1924f2b28`
