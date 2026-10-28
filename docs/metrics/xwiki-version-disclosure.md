# Metrics: xwiki-version-disclosure

## Overview
Detects XWiki markers or /xwiki/bin/ paths; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled XWiki instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `ad3a2ff3a03948bc91aa827938f3291dfb58ed70c626f5f19cb87891b7d5dd65`
