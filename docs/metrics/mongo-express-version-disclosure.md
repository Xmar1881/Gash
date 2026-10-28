# Metrics: mongo-express-version-disclosure

## Overview
Detects Mongo Express markers on the admin UI; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Mongo Express instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `8c13667ea460649275ebda1327469d11ff50eed5ff099d54761f326bebe741b5`
