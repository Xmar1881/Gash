# Metrics: vikunja-version-disclosure

## Overview
Detects the Vikunja frontend_url field on the public info API; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Vikunja instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `ad690fec4f2964f025d36e36295372dbceee60b2adff9179270f3b13376eb76c`
