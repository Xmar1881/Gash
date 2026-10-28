# Metrics: osticket-version-disclosure

## Overview
Detects osTicket markers on the staff login path; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled osTicket instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `14963afb85055a101ad9790c8ce60c1a26c069bdc8fbfbf11b25202142b6fe95`
