# Metrics: trac-version-disclosure

## Overview
Detects Trac generator metadata or /trac/ paths; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Trac instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `c97e497f81b162e355b61ca65968a9680a30971dc3a21886e2bc3f3c7ece43a8`
