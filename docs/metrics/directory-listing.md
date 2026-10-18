# Metrics: directory-listing

## Overview

Tier 1 plugin (GASH-059, CWE-548). Fixed directory path list probed with GET;
each path triggering a title match pays one soft-404 control request.

## Evidence Standard

Firm ceiling. Accept requires a server listing title (`<title>Index of ...`
or `<title>Directory listing for ...`) in the 200 body; the same marker must
be absent from the soft-404 control of the same path. Custom pages that
mention "index of" in body text but not in the title stay clean.

## Fixtures

- Positive: 2 of 2 accepted (Apache `Index of /`, Python http.server
  `Directory listing for /`), both firm.
- Negative: 2 of 2 rejected (uploads page mentioning a disabled index, WAF).

## Corpus Result

No unexpected firm plus. The shared guard rejects WAF-classified responses;
the title-only signature avoids matching prose mentions.

## Lab Result

Pending manual run against an nginx/Apache lab with `autoindex on`.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate.

## Dataset

- Dataset hash: `b380b3fd7edcccf0fc9f581b63c7f724174fb46d13d351a16be144e2b1257397`
  (sha256 over all 4 fixture files).
- Samples: TP=2, FP=0, TN=2, FN=0.

## Limitations

- Firm ceiling: single-channel content observation, never confirmed.
- Directory names outside the fixed path list are missed by design (no
  crawling).
- Custom-styled listing pages without the stock title marker are not detected.
