# Metrics: nextjs-image-optimizer-ssrf

## Overview

Tier 1 plugin (GASH-070, CWE-918). OOB-required: without `--oob-server` the
engine never schedules it and no tentative placeholder is produced. The plugin
requests `/_next/image` with `url={{OOB_URL}}` plus the companion `w`/`q`
parameters required by the optimizer.

## Evidence Standard

Confirmed only through a real callback to the operator's self-hosted OOB
server. The callback proves that the image optimizer fetched the supplied URL
server-side. Internal, localhost, and cloud-metadata targets are deliberately
not probed, and the plugin is marked `safe: false` because a successful
callback means the server made an outbound request.

## Fixtures

- Positive: 1 of 1 accepted (OOB callback recorded with correlation ID and
  namespace), confirmed.
- Negative: 3 of 3 rejected (400 `url parameter is not allowed`, 200
  placeholder image without a callback, 404 route without a callback).

## Corpus Result

No unexpected firm plus. Without a provider no request is sent; with a
provider, a missing callback can only reject. A non-callback response never
upgrades to a finding.

## Lab Result

Pending manual run against a Next.js application with the default image
optimizer and a self-hosted OOB server.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate.

## Dataset

- Dataset hash: `edd478812c2dc6b6c5bdc5d4fa08a82c7cb274f4ff678c2b19006ec1a38fa1cf`
  (sha256 over all 4 fixture files).
- Samples: TP=1, FP=0, TN=3, FN=0.

## Limitations

- Callback confirms one server-side fetch, not arbitrary internal network
  access or metadata credential theft; those targets are out of scope by
  design.
- Next.js remote image allowlists and self-hosted loaders may reject the OOB
  host, producing an honest negative.
- The optimizer may cache a fetched image; a later scan with a fresh token is
  unaffected because each attempt uses a single-use URL.
