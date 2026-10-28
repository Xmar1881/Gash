# Metrics: jenkins-version-disclosure

## Overview
Detects the Jenkins version response header on public Jenkins roots; banner-only fingerprint, tentative confidence.

## Corpus
Precision 1.00; One positive banner fixture and one generic negative fixture; the fingerprint is banner-only.

## Lab
Pending manual run against a controlled Jenkins instance; no live measurement is claimed.

## Precision
True positives 1, false positives 0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Precision is above the 0.99 gate.

## Dataset
- Dataset hash: `c4ad25ed49bdbaee20d18df59e740e8fea026a6ebf8eed419f7dd71461aff983`
