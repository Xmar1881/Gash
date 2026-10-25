# Metrics: csp-unsafe-directives

## Overview
Passive `header/policy` check for `unsafe-inline` and `unsafe-eval` CSP directives.

## Corpus
Precision 1.00; unsafe directives are firm and a strict policy is rejected.

## Lab
Pending manual run against a controlled web application.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
`47dca76c13d71587726bfd84827c6b253c6bf1fa180a8af1fd25f5f51cf58adb`
