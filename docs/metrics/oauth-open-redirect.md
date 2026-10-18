# Metrics: oauth-open-redirect

## Overview

Tier 1 plugin (GASH-063, CWE-601). Fixed authorize paths combined with the
standard redirect parameter names; GET only, no consent flow is attempted.

## Evidence Standard

Confirmed when the Location header points at the loopback-independent canary
host (`gash-canary.example`) and the neutral-parameter control does not
produce an absolute redirect; firm when the control is unavailable. A
relative Location or any other host is rejected: the oracle only accepts a
Location whose hostname equals the payload host.

## Fixtures

- Positive: 2 of 2 accepted (302 to canary host with clean 200 control, 301
  with uppercase host), both confirmed.
- Negative: 3 of 3 rejected (relative `/login` redirect, redirect to another
  host, login page without Location).

## Corpus Result

No unexpected firm plus; host equality plus control absence gates the claim.

## Lab Result

Pending manual run against an OAuth lab with an unvalidated redirect_uri.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate.

## Dataset

- Dataset hash: `d8ce08d09576fe9432264c37dd9ad531f84f69cc5cd8e4db718f28e01791896c`
  (sha256 over all 5 fixture files).
- Samples: TP=2, FP=0, TN=3, FN=0.

## Limitations

- The neutral-value control is sent against the base target, not the probed
  path; apps that redirect the base target absolutely downgrade the finding
  to firm instead of confirmed.
- Authorize endpoints on nonstandard paths are missed by design (no
  crawling).
