# Metrics: typo3-version-disclosure

## Overview
Detects TYPO3 generator metadata or typo3temp/typo3conf asset paths; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled TYPO3 instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `337ab7d6757c5aec6bef83b4ffb2bfda63c4ef0355523e934490308a55fe9c93`
