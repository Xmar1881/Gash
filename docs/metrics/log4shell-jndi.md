# Metrics: log4shell-jndi

## Overview

Tier 1 plugin (GASH-060, CWE-917). OOB-required: without `--oob-server` the
engine never schedules it and no tentative placeholder is produced.

## Evidence Standard

Confirmed only through a real callback. Every attempt mints a single-use
correlation token; the LDAP URL, deobfuscated `${lower:l}dap`, and DNS
variants are expanded per attempt in the query payload and in the
User-Agent/X-Api-Version request headers. A token that never fires yields no
finding at all; a callback confirms server-side JNDI lookup construction.

## Fixtures

- Positive: 2 of 2 accepted (User-Agent LDAP callback, parameter DNS
  callback), both confirmed.
- Negative: 2 of 2 rejected (no callback, WAF block without callback).

## Corpus Result

No unexpected firm plus. Callback absence can only ever reject; the shared
guard rejects WAF-classified responses even when a callback is simulated.

## Lab Result

Pending manual run against a Log4j 2.14 lab with a self-hosted OOB server.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate.

## Dataset

- Dataset hash: `8c195e4bc7e682a049d419cd6ca508b2a23ad8f6c694819c0db3c85dd40bba69`
  (sha256 over all 4 fixture files).
- Samples: TP=2, FP=0, TN=2, FN=0.

## Limitations

- Header and query vectors share one correlation token per attempt; the
  finding attributes the header carrier when one is declared (vector field
  records `query+header` when both were sent).
- DNS-only resolution on the OOB side still counts as proof of lookup
  construction, not of full LDAP exploitation.
- Patched Log4j versions that log the literal text produce no callback.
