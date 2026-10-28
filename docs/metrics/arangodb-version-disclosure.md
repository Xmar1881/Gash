# Metrics: arangodb-version-disclosure

## Overview
Detects ArangoDB markers or system database paths; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled ArangoDB instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `81fe4e33c6f6c6aef5aca8af386a47aa512e3ce58810fddefcc6bffcf5ea418c`
