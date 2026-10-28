# Metrics: phpldapadmin-version-disclosure

## Overview
Detects phpLDAPadmin markers or template asset paths; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled phpLDAPadmin instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `bfc0ce824b411e02fe9d201d390c64ac446aebf58641ccd1c7c6ce2a656be564`
