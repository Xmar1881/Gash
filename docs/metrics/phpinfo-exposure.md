# Metrics: phpinfo-exposure

## Overview

Tier 1 plugin (GASH-057, CWE-200). Fixed path list probed with GET; each path
triggering a body match pays one soft-404 control request.

## Evidence Standard

Firm ceiling. Accept requires a phpinfo table/title marker (`phpinfo()</title>`,
`PHP Version =>`, `Configuration File (php.ini) Path`, `Loaded Configuration
File`) in the 200 body; the same marker must be absent from the soft-404
control of the same path. A bare 200, a 404/500, or a page that merely
mentions "phpinfo" never reaches firm.

## Fixtures

- Positive: 2 of 2 accepted (HTML table page, CLI text dump), both firm.
- Negative: 2 of 2 rejected (marker-free page that mentions phpinfo, WAF block).

## Corpus Result

No unexpected firm plus. The shared guard rejects WAF-classified responses
before signatures are evaluated; the soft-404 control strips SPA catch-alls.

## Lab Result

Pending manual run against an intentionally exposed phpinfo lab container.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate.

## Dataset

- Dataset hash: `1aadbab3a1ff9fabc6c3415dea7109c33c01abdc81c9032d78871767dad44f67`
  (sha256 over all 4 fixture files).
- Samples: TP=2, FP=0, TN=2, FN=0.

## Limitations

- Firm ceiling: single-channel content observation, never confirmed.
- A server that maps the `.gash-soft404-check` suffix onto the same handler
  (e.g. aggressive MultiViews rewrites) can suppress a true positive.
- Nonstandard phpinfo filenames outside the fixed path list are missed by
  design (no crawling).
