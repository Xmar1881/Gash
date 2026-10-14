<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / Gash contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/lab-compose-dvwa-juiceshop-2026-10-14.md
What: Compose-lab recall procedure and BLOCKED status without a docker runtime.
Why: DVWA/Juice Shop recall stays unmeasured where docker is absent; the
procedure is filed so any docker host can reproduce it byte-identical.
-->

# Lab: compose DVWA / Juice Shop (2026-10-14, BLOCKED)

## Status

BLOCKED — no docker runtime in this environment (`docker --version` fails).
No compose service was started, no aggressive scan was run against DVWA or
Juice Shop, and no recall number is claimed. The localhost synthetic lab
(`lab-aggressive-local-2026-10-14.md`) remains the only measured recall.

## Pinned Lab

`docker-compose.lab.yml` (repo root, localhost-only):

- `dvwa`: `vulnerables/web-dvwa:2.0` on `127.0.0.1:8081:80`
- `juiceshop`: `bkimminich/juice-shop:17.1.0` on `127.0.0.1:8082:3000`
- `webgoat`: `webgoat/webgoat:2023.8` on `127.0.0.1:8083:8080`
- Network `gash-lab` internal; no `latest` tag anywhere.

## Reproduction Procedure (docker host)

Only on targets you own or have explicit written permission to test; the
compose lab is localhost-only by design.

```sh
docker compose -f docker-compose.lab.yml up -d
docker compose -f docker-compose.lab.yml ps
go run ./cmd/gash scan --target http://127.0.0.1:8081 --aggressive --scope 127.0.0.1 --format json --output lab-dvwa.json
go run ./cmd/gash scan --target http://127.0.0.1:8082 --aggressive --scope 127.0.0.1 --format json --output lab-juiceshop.json
docker compose -f docker-compose.lab.yml down
```

Count per-class findings (SQLi, XSS, command injection on DVWA; injection,
auth, misconfig on Juice Shop), file the recall next to this report as
`docs/metrics/lab-compose-*.md` with Precision, Recall, Corpus, Lab, and
Gate Verdict sections, and link it from `docs/metrics/README.md`.

## Precision

Unmeasured (BLOCKED).

## Recall

Unmeasured (BLOCKED).

## Corpus

Unaffected: `TestB4CorpusZeroFirmPlus` still holds 0 `firm` plus on clean,
SPA, WAF, encoded, and dynamic bodies.

## Gate Verdict

BLOCKED. No gate passes or fails on compose recall until the procedure above
runs where docker exists.

## Dataset

- Compose file: `docker-compose.lab.yml` (pinned digests per service).
- Scan artifacts: none (no run).
