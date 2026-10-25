# Metrics: aws-credentials-exposure

## Overview
Fixed-path AWS credential profile exposure check using `critical_exposure`.

## Corpus
Precision 1.00; canonical access-key markers accepted, neutral response rejected.

## Lab
Pending controlled document-root run.

## Precision
TP=1, FP=0. Precision 1.00.

## Recall
Fixture recall 1/1. Recall 1.00.

## Gate Verdict
PASS. Evidence ceiling is `firm`; this is not RCE proof.

## Dataset
`d8b993e52ad0e9b9930ef4497312aa051476890a6c56c3490a9858a8ccd0971f`
