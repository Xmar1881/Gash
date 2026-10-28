# Metrics: phpbb-version-disclosure

## Overview
Detects phpBB footer or core stylesheet markers; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled phpBB instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `1d26bad92f09c337e79ee51879e20d462f5af23cc47a944fbba8e9aa779f022b`
