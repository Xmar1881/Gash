# Metrics: gerrit-version-disclosure

## Overview
Detects Gerrit Code Review markers or /gerrit/ paths; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Gerrit instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `cb63dae108c15a78d5c3e316359224e4c89240a57c2fa9c0de6bdb90aeb254e7`
