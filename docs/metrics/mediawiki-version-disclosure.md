# Metrics: mediawiki-version-disclosure

## Overview
Detects MediaWiki generator metadata or load.php module paths; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled MediaWiki instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `fa930de247750f6801b1b3299b0a1553bcb29fdfaf7c87831a306382e99f2201`
