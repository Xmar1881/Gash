# Metrics: ssi-injection

## Overview

Tier 1 plugin (GASH-064, CWE-97). `<!--#printenv -->` plus a
`DATE_LOCAL` echo variant across six common parameter names.

## Evidence Standard

Firm ceiling. Accept requires two distinct CGI variables from a printenv
block (`GATEWAY_INTERFACE` plus `SERVER_SOFTWARE`/`DOCUMENT_ROOT`/
`SCRIPT_FILENAME` in one bounded window) in the response body with the
neutral-parameter control free of the marker. A literal directive echo
contains no CGI variables; generic `$_SERVER` debug dumps lack the required
GATEWAY_INTERFACE pairing.

## Fixtures

- Positive: 2 of 2 accepted (printenv with SERVER_SOFTWARE, printenv with
  DOCUMENT_ROOT), both firm.
- Negative: 3 of 3 rejected (literal directive echo, env debug page without
  the GATEWAY_INTERFACE marker, WAF).

## Corpus Result

No unexpected firm plus; the two-variable signature is not reachable from
clean bodies.

## Lab Result

Pending manual run against an Apache lab with `Options Includes`.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate.

## Dataset

- Dataset hash: `314147c85123a8a3ccb7ef5f7ea76df74130e5fbe052029789a81d8a678c3e02`
  (sha256 over all 5 fixture files).
- Samples: TP=2, FP=0, TN=3, FN=0.

## Limitations

- Firm ceiling: single-channel content observation, never confirmed.
- echo/printenv payloads only; `#exec` and file-writing directives are out
  of policy and untested by design.
- Servers that strip CGI variables from printenv output can still be
  vulnerable without reaching this signature.
