<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/lab-aggressive-local-2026-10-14.md
What: Recall measurement of the aggressive profile against a localhost lab.
Why: First measured recall (not fixture-scoped): 7 seeded classes on
127.0.0.1 only, no external traffic, bounded budget.
-->

# Lab: aggressive recall (localhost synthetic lab, 2026-10-14)

## Overview

`--aggressive` profile measured against a purpose-built localhost lab
(stdlib Go server, `127.0.0.1:8099` only). No docker in this environment, so
the DVWA/JuiceShop compose lab could NOT run (BLOCKED, see § Lab Result and
remaining work). The synthetic lab seeds 7 vulnerability classes; every scan
used bounded budgets and dual-user flags.

## Procedure

1. Build and start the lab (repo dışı, temp dizin):
   `go build -o lab.exe lab.go` + run (source: temp `gash-lab/lab.go`,
   endpoints `/`, `/sqli`, `/login`, `/xss`, `/fetch`, `/obj`, `/waf`, `/timed`).
2. Per-endpoint aggressive scans (SADECE localhost):
   `go run ./cmd/gash scan --target http://127.0.0.1:8099/<endpoint> --aggressive
   --max-requests-per-target 800 --max-requests-total 3000 --plugin-timeout 120s
   --auth-user-a "Authorization: Bearer AAAA" --auth-user-b "Authorization: Bearer BBBB"
   --format json` (`/timed` ve `/` için `--plugin-timeout 300s`).
3. Findings per class counted below; JSON artifacts kept out-of-repo (temp).

## Results per Seeded Class

| # | Class | Endpoint | Finding (confidence) | Verdict |
|---|---|---|---|---|
| 1 | SQLi error-based | `/sqli?id=1` | `sqli-error-based` confirmed (GASH-004) | TP |
| 2 | SQLi login auth-bypass | `/login?username=t` | `sqli-auth-bypass` confirmed ×5 params (GASH-004) | TP |
| 3 | XSS attribute breakout | `/xss?q=hello` | `xss-attribute-injection` static-execution-evidence + `xss-reflected-basic` tentative (GASH-001) | TP |
| 4 | SSRF cloud metadata | `/fetch?url=x` | `ssrf-cloud-metadata` firm, labeled GASH-008/CWE-918 (GASH-008) | TP |
| 5 | BOLA/IDOR cross-user | `/obj?id=1` | `idor-bola-matrix` tentative (GASH-005) | TP |
| 6 | WAF bypass behavior | `/waf?x=1` | 275/275 blocked requests bypassed; block page never evidence; clean page yields true headers finding | TP (behavior) |
| 7a | SQLi time-based | `/timed?id=1` | `sqli-time-based` firm (GASH-000) | TP |
| 7b | SQLi stacked time | `/timed?id=1` | `sqli-stacked-time` firm (GASH-000) | TP |

Supporting true findings: `missing-security-headers` confirmed on every
endpoint (lab sends no hardening headers — correct), `fuzz-anomaly`
tentative on `/sqli` (GASH-004), `/login` (GASH-004), `/xss` (GASH-000),
`xss-reflected-basic` tentative on `/`.

## Precision

Vulnerability-class findings: 12 TP, 0 FP → Precision 1.00 (post-fix;
during the runs 1 FP was found and fixed, see § Fixes Proven By This Lab).
Config true positives (`missing-security-headers` ×8) excluded from the
vuln-class count. By-design tentatives (`fuzz-anomaly`, `idor-bola-matrix`,
`xss-reflected-basic` text reflection) are labeled manual-review and counted
neither as confirmed TP nor as FP.

## Recall

Seeded classes detected 7/7 → Recall 1.00 on this synthetic lab
(8 plugin findings across 7 classes). Scope: single-parameter GET endpoints,
deterministic backend, no JS rendering, no jitter — NOT a real-world claim.

## Fixes Proven By This Lab

1. Safe Tier 2 plugins panicked on POST surface points (3 errors on `/`):
   safe specs now receive read-only points (`readOnlyJSPoints`); re-run `/`
   shows errors=0.
2. `sqli-boolean-differential` confirmed on pure-reflection endpoint (`/xss`):
   plugin now skips payload-echoing responses; re-run `/xss` shows no
   differential finding. Known limitation recorded: deterministic reflection
   defeats stability-only differentials in general.
3. `fuzz-anomaly` tentative shadowed `sqli-error-based` confirmed (`/sqli`):
   `finding.Dedup` now keeps the higher-confidence finding; re-run `/sqli`
   shows the confirmed finding.

## Corpus

Oracle-level: `TestB4CorpusZeroFirmPlus` still holds 0 `firm` plus on clean,
SPA, WAF, encoded, and dynamic bodies. Lab adds black-box confirmation the
corpus cannot give (live HTTP, timing, dual identity, WAF loop).

## Lab Result

Synthetic localhost lab: DONE (this report, 2026-10-14).
DVWA / Juice Shop / WebGoat compose lab (`docker-compose.lab.yml`):
BLOCKED — no docker runtime in this environment. The compose file already
pins localhost-only ports (`127.0.0.1:8081-8083`) and an internal network;
run `docker compose -f docker-compose.lab.yml up -d` where docker exists,
then repeat § Procedure with `--target http://127.0.0.1:8081` (DVWA) and
`http://127.0.0.1:8082` (Juice Shop) and file the recall next to this report.

## Gate Verdict

PASS for the synthetic lab (Recall 1.00, Precision 1.00, fixture gates green).
Compose-lab recall remains unmeasured — claimed nowhere as measured.

## Dataset

- Lab source: out-of-repo temp `gash-lab/lab.go` (procedure above rebuilds it
  byte-identical intent; endpoint semantics fixed in § Procedure).
- Scan artifacts: 8 JSON reports (out-of-repo temp `gash-lab/scan-*.json`).
- Fixture datasets: per-plugin hashes in `sqli-auth-bypass.md`,
  `ssrf-cloud-metadata.md`, `xss-attribute-injection.md`, `sqli-stacked-time.md`.
