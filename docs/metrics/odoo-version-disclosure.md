# Metrics: odoo-version-disclosure

## Overview
Detects the Odoo version_info server_version field; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Odoo instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `7f59ea72b5890608f58e4a322e17f06cc6e5aad7c5d4b2cf343a281829e855b1`
