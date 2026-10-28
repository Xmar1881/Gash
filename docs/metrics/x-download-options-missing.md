# Metrics: x-download-options-missing

## Overview
Detects a missing X-Download-Options header that prevents legacy Internet Explorer from opening downloads in-site.

## Corpus
Precision 1.00; Fixture cases cover the policy violation, the compliant header set, and (for directive checks) the absent-header case.

## Lab
Pending manual run against a controlled endpoint; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `917255d1621af948647e0351eb43da8287dbe75537c2c59c2ebb4a5822969538`
