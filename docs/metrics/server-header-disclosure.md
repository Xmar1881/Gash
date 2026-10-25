# Metrics: server-header-disclosure

## Overview
Passive `header/policy` check for the origin `Server` response header.

## Corpus
Precision 1.00; a fingerprinting header is firm and its absence is clean.

## Lab
Pending manual run against a controlled web application.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
`fc5c52efd8d03654004fdaf32896febf28a7ba92744187b7c9ba21c9b8032a85`
