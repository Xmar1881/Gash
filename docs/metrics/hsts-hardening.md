# Metrics: hsts-hardening

## Overview
Passive `header/policy` check for long-lived HSTS and `includeSubDomains`.

## Corpus
Precision 1.00; weak HSTS is firm and the hardened policy is rejected.

## Lab
Pending manual run against a controlled HTTPS application.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
`dd235fbacb944a953945abe6042c8d0daf5e454c903aa67b2a9f0166eea2d659`
