# Metrics: umbraco-version-disclosure

## Overview
Detects Umbraco admin paths or XSRF cookie markers; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Umbraco instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `ee9ee57745ad66d01288d60b39f982e52af1edff561d86bb1ae494c76452adcc`
