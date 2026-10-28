# Metrics: bugzilla-version-disclosure

## Overview
Detects Bugzilla markers or buglist.cgi endpoints; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Bugzilla instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `19dd37c42b00ed7231d22f6f5bb911d48bdd9899e3fa98c5e80115c0af3e2312`
