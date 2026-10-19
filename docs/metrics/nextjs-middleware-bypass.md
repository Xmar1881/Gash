# Metrics: nextjs-middleware-bypass

## Overview

Tier 1 plugin (GASH-069, CWE-288) for CVE-2025-29927. GET-only differential
probe over `/admin`, `/dashboard`, `/api/user`, `/account`, and `/settings`.
The control request contains no bypass header; variants carry a declared
`x-middleware-subrequest` value. No OOB server and no credentials are needed.

## Evidence Standard

A finding requires all of the following: the control response is access-denied
(401/403 or a redirect to a login/session path), the bypass response is 2xx,
its trimmed body has at least 32 characters, and the masked body differs
from the control body. Header echo with an unchanged login redirect, identical
block content, WAF/challenge pages, and public 200-to-200 routes are rejects.
The oracle contributes the firm confidence ceiling; no payload validation or
credential access is attempted.

## Fixtures

- Positive: 2 of 2 accepted (302 login redirect to 200 admin content, 401 to
  200 protected account content), both firm.
- Negative: 4 of 4 rejected (header echoed but still redirected, identical
  block body, Cloudflare/WAF block page, public 200-to-200 route).

## Corpus Result

No unexpected firm plus. The control-denied gate prevents public routes from
reaching variant requests, and the saved-request loop stops after the first
accepted header value per path.

## Lab Result

Pending manual run against a Next.js 14 application using middleware-based
authorization. Scope is intentionally limited to app-level middleware checks;
patched versions that reject forged subrequest headers produce no finding.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate.

## Dataset

- Dataset hash: `7c9460f50534c48564f835bf26212dde85b50a66cda39c37cda4c1adf39abd7f`
  (sha256 over all 6 fixture files).
- Samples: TP=2, FP=0, TN=4, FN=0.

## Limitations

- CVE-2025-29927 affects specific Next.js versions and middleware layouts;
  finding the bypass header does not prove every protected path is reachable.
- Applications that enforce authorization inside route handlers in addition to
  middleware are correctly not bypassed by this header and stay silent.
- A control redirect must be identifiable as login/session/auth; custom SSO
  paths without those segments are treated as not protected and skipped.
