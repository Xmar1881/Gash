# Metrics: content-type-options-missing

## Overview
Passive `header/policy` check for `X-Content-Type-Options: nosniff`.

## Corpus
Precision 1.00; missing `nosniff` is accepted and the protected response is rejected.

## Lab
Pending manual run against a controlled web application.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
`fb7c3c229a92bd680cb14e01b82444b5a8f796f03af2e471d8ae5bb96fcbafd4`
