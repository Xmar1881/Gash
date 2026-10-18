# Metrics: webdav-enabled

## Overview

Tier 1 plugin (GASH-065, CWE-650). OPTIONS requests against `/`, `/dav/`,
and `/webdav/`; the claim rests on the server's own Allow advertisement.

## Evidence Standard

Confirmed when the Allow header advertises at least one write method
(PUT, DELETE, MOVE, COPY, MKCOL, PROPPATCH). Read-only advertisements
(GET/HEAD/OPTIONS/POST/PROPFIND), missing Allow headers, and WAF-classified
responses never accept. No write request is ever sent: OPTIONS is idempotent
and safe, so the plugin stays `safe: true`.

## Fixtures

- Positive: 2 of 2 accepted (collection Allow with PUT/DELETE, multistatus
  Allow with MKCOL/MOVE/COPY), both confirmed.
- Negative: 3 of 3 rejected (read-only Allow, missing Allow, WAF block).

## Corpus Result

No unexpected firm plus; clean corpus responses carry no Allow header.

## Lab Result

Pending manual run against an Apache/nginx WebDAV lab.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate.

## Dataset

- Dataset hash: `d540e2b53b88fe255e76c3327e266a6ca8e60a1a50db59c8d38cc9002c1d6d2b`
  (sha256 over all 5 fixture files).
- Samples: TP=2, FP=0, TN=3, FN=0.

## Limitations

- An auth-walled DAV share still advertises write methods; the finding is
  "write-capable endpoint exposed", not "anonymous write proven".
- Endpoints outside the fixed path list are missed by design (no crawling).
