# Metrics: authelia-version-disclosure

## Overview
Detects Authelia markers on public login pages; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Authelia instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `9684ec0ebb6619a4cb12dd5f1482d650dfd5ae58211b307a71ae7f779e082c4c`
