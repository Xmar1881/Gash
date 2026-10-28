# Metrics: nats-version-disclosure

## Overview
Detects the NATS server_name field on the monitoring varz endpoint; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled NATS instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `7bf24e9cb41123dba03830c9f3032126141b6483b0fdc22662425671cf5a5c58`
