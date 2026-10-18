# Metrics: management-endpoint-exposure

## Overview

Tier 1 plugin (GASH-058, CWE-200). Fixed actuator/console path list probed
with GET; each path triggering a body match pays one soft-404 control request.

## Evidence Standard

Firm ceiling. Accept requires a management body marker (`activeProfiles`,
`propertySources`, `beans`, `mappings`, `traces`, `JAVA PROFILE 1.0.x`,
`Apache Server Status`, `Tomcat Manager Application`, `H2 Console`) in the
200 body; the same marker must be absent from the soft-404 control of the
same path. Disabled-actuator JSON 404s carry no marker and stay clean.

## Fixtures

- Positive: 3 of 3 accepted (actuator env JSON, heapdump header, server-status),
  all firm.
- Negative: 3 of 3 rejected (disabled actuator JSON 404, SPA catch-all, WAF).

## Corpus Result

No unexpected firm plus. The shared guard rejects WAF-classified responses;
the soft-404 control strips SPA catch-alls that answer 200 on unknown paths.

## Lab Result

Pending manual run against a Spring Boot lab with actuator exposed.

## Precision

True positives 3, false positives 0. Precision 1.00.

## Recall

True positives 3, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate.

## Dataset

- Dataset hash: `6448a99a06e3e870fc74573cd715a8b0f6f69fbfa6d4a149ab9a901f494cc105`
  (sha256 over all 6 fixture files).
- Samples: TP=3, FP=0, TN=3, FN=0.

## Limitations

- Firm ceiling: single-channel content observation, never confirmed.
- Actuator endpoints on custom base paths (`management.endpoints.web.base-path`)
  are missed by design (no crawling).
- No `requires_tech` gate: enough servers hide framework fingerprints that a
  tech requirement would cost more recall than it saves.
