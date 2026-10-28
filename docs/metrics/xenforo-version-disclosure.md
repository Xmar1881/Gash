# Metrics: xenforo-version-disclosure

## Overview
Detects XenForo script assets or data-xf attributes; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled XenForo instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `3357af099706701d51068c66aa922567a09fbf09e8336646cfc8d41e02381498`
