# Metrics: mybb-version-disclosure

## Overview
Detects MyBB footer or jscripts asset paths; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled MyBB instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `36253f4130a9bd53aff144b26705c486faaaba9d34162154851fa6d7574390c2`
