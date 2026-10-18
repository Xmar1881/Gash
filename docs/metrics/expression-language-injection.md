# Metrics: expression-language-injection

## Overview

Tier 1 plugin (GASH-061, CWE-917). Payload family `${1337*1337}`,
`#{1337*1337}`, `*{1337*1337}`, `%{1337*1337}` mapped to the product canary
`1787569`; four common parameter names.

## Evidence Standard

Firm ceiling. Accept requires the product canary (7-digit arithmetic result)
in an allowed HTML text or HTML attribute context, with the oracle's JSON
block rejection applying. A literal payload echo never contains the product;
control bodies protect the attribute path. The 7-digit canary keeps
coincidental text matches rare.

## Fixtures

- Positive: 2 of 2 accepted (product in HTML text, product in input value
  attribute with clean control), both firm.
- Negative: 4 of 4 rejected (literal `${...}` echo, product inside inline
  script context, JSON response body, WAF).

## Corpus Result

No unexpected firm plus: clean corpus bodies contain neither the product
canary nor expression markers.

## Lab Result

Pending manual run against a SpEL/Thymeleaf lab endpoint.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate.

## Dataset

- Dataset hash: `874786b12ef7c194586d76849a47d3e5b62da4939c4b85fe414723908376ed3f`
  (sha256 over all 6 fixture files).
- Samples: TP=2, FP=0, TN=4, FN=0.

## Limitations

- Firm ceiling, single observation; never confirmed and no browser proof.
- HTML text reflection is accepted without a control comparison (oracle
  behavior for text context); the distinctive product canary is the only
  guard there.
- JSON API responses that evaluate expressions are rejected by the oracle's
  JSON block rule.
- Engine-side evaluation of string-typed fields that do not land in an HTML
  context is out of scope for this screen.
