# Metrics: druid-version-disclosure

## Overview
Detects Apache Druid markers or unified-console paths; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Apache Druid instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `369dc4946f027f09af6f6e066bb5033ff2c997188a78813b38890cfd13b24f32`
