# Metrics: prestashop-version-disclosure

## Overview
Detects PrestaShop generator metadata in public responses; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled PrestaShop instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `c7db0591b4d717404461e2383fb0fcf79d03b2ab99f5f1ff821ce5769ec71a25`
