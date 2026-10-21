<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/native-lab-2026-10-20.md
What: Final native-lab benchmark on Juice Shop, DVWA, and WebGoat.
Why: Records the measured Gash/Nuclei comparison with independent
  verification, exact conditions, and honest limitations.
-->

# Native Lab Benchmark (2026-10-20)

## Status

Measured and verified. Three real applications ran as native Windows
processes (no Docker): OWASP Juice Shop 17.1.0 on `127.0.0.1:8082`, DVWA on
`127.0.0.1:8081`, and WebGoat 2023.8 on `127.0.0.1:8083`. Each of the 22
scenarios was independently verified before scoring; `unverified=0` in both
final runs. This is a controlled lab measurement, not a general
superiority claim.

> **2026-10-21 update:** hash/fragment route discovery, the browser execution
> probe, and benchmark finding dedupe were implemented after this run. The
> numbers below are the pre-fix baseline and have **not** been re-measured;
> do not quote them as current behavior. In particular, the
> `juiceshop-xss-dom-search` miss reflects the old discovery gap. A fresh
> standard/deep run and artifact/hash refresh are required before the result
> is final.

## Final Metrics

| run | tool | findings | tentative | TP | FP | TN | FN | precision | recall | F1 | duration | requests |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| standard | Gash | 52 | 31 | 11 | 0 | 9 | 2 | 1.000 | 0.846 | 0.917 | 2m8.835s | 6,676 |
| standard | Nuclei 3.11.1 | 11 | 0 | 5 | 0 | 9 | 8 | 1.000 | 0.385 | 0.556 | 55.886s | N/A |
| deep | Gash | 89 | 34 | 12 | 0 | 9 | 1 | 1.000 | 0.923 | 0.960 | 2m42.406s | 7,866 |
| deep | Nuclei 3.11.1 | 11 | 0 | 5 | 0 | 9 | 8 | 1.000 | 0.385 | 0.556 | 57.121s | N/A |

Precision is scenario-scoped. Unmatched findings are listed separately and
are not counted as false positives: standard `unmatched=10`, `excluded=17`;
deep `unmatched=11`, `excluded=50`.

Both Gash reports have `confirmed_tp=0` even though every vulnerable scenario
was independently verified. The scored Gash findings are detector evidence,
not tool-tagged browser-confirmed evidence; the benchmark's `browser-exec`
verification is a separate check. Do not describe those TPs as
browser-confirmed discoveries.

## Per Category

| category | scenarios | standard Gash | deep Gash | Nuclei |
|---|---:|---|---|---|
| clean | 9 | TN=9 | TN=9 | TN=9 |
| exposure | 6 | TP=6 | TP=6 | FN=6 |
| sqli | 3 | TP=3 | TP=3 | TP=3 |
| lfi | 1 | TP=1 | TP=1 | TP=1 |
| xss-reflected | 1 | TP=1 | TP=1 | TP=1 |
| xss-dom | 2 | FN=2 | TP=1, FN=1 | FN=2 |

Standard FNs: `juiceshop-xss-dom-search`, `dvwa-xss-dom`. Deep FN:
`juiceshop-xss-dom-search`. Nuclei's 8 FNs are the 6 exposure scenarios and
both DOM-XSS scenarios.

## Cross-Tool

| run | both | Gash-only | Nuclei-only | neither |
|---|---:|---:|---:|---:|
| standard | 5 | 6 | 0 | 11 |
| deep | 5 | 7 | 0 | 10 |

The five shared TPs are both SQLi scenarios, the blind SQLi scenario, the LFI
scenario, and reflected XSS. Gash-only TPs are the six exposure scenarios
(deep adds DVWA DOM XSS). All nine expected-clean scenarios are TN for both
tools; no false positives were scored in either direction.

## Conditions

- Dataset: 22 scenarios across 3 targets, with fresh DVWA sessions for admin
  and `gordonb`.
- Gash standard: `--profile standard --active --rate-limit 80
  --plugin-timeout 20s --request-timeout 2s --max-requests-total 6000
  --max-requests-per-target 3000 --scope 127.0.0.1,localhost`.
- Gash deep: `--profile deep --deep --browser-verify --active --rate-limit 80
  --plugin-timeout 40s --request-timeout 5s --max-requests-total 12000
  --max-requests-per-target 6000 --scope 127.0.0.1,localhost`.
- Nuclei: v3.11.1, tags `xss,sqli,lfi,rce,redirect,exposure`, `-dast`,
  `-fa high`, rate limit 80, 10-minute wall-clock timeout. Nuclei cannot cap
  total requests; this is an upstream limitation, not an equalization claim.
- Both tools ran sequentially against the same base URLs. DVWA was scanned
  without auth and with both user sessions; Juice Shop and WebGoat were
  scanned without auth. Nuclei received the same explicit seeds (8 Juice
  Shop, 9 DVWA, 0 WebGoat).
- Gash has a crawler and discovery phase; Nuclei does not. That difference is
  part of the measured tool behavior, not normalized away.
- Browser verification in both reports was performed by the `-tags deep`
  runner. The standard scan binary itself does not link Chrome.

## DOM XSS

In this pre-fix run, `dvwa-xss-dom` was an FN in the standard profile and a
TP in deep via `dom-sink-basic`. Its finding was on the correct
`/vulnerabilities/xss_d/` path. `juiceshop-xss-dom-search` was an FN in both
profiles. The route is `/#/search?q=...`; the old browser crawl fetched three
pages, five endpoints, and zero forms, did not click or type, and did not
follow hash-only routes. A separate controlled browser check confirmed the
underlying Juice Shop DOM execution, so this was a discovery gap, not a
verification failure. The 2026-10-21 hash-route changes target exactly this
gap; re-measurement is pending.

## LFI And RFI

`dvwa-lfi` is a TP for both tools. On this Windows host, forward-slash
traversal did not yield `win.ini`; the live run used a Windows relative
traversal and the checked-in dataset uses `C:\Windows\win.ini`. The content
signature is `windows_ini`, not an include warning.

`file-inclusion-rfi` and `rfi-remote-include` now require an executable
context and therefore cap live URL reflection at `tentative`. DVWA reflected
the loopback canary on `/vulnerabilities/fi`, but `allow_url_include=Off`, so
there is no inclusion proof. Those tentative findings are declared unscored
in the dataset and are not counted for either tool.

## Exclusions And Limits

- Excluded findings are outside the declared scenario classes: security
  headers, CORS, clickjacking, cookie flags, HPP, cache poisoning, template
  reflection, and similar surface checks. They are listed in the reports for
  transparency, never scored as FPs.
- Nuclei has no crawler and no independent scope enforcement; comparison
  depends on the explicit seed list and tags.
- WebGoat contributes one expected-clean login-page scenario; broad WebGoat
  lesson coverage is not claimed.
- In this pre-fix run, Juice Shop SPA discovery remained weaker than its DOM
  surface; the hash-route follow-up is implemented but not yet re-measured.
- No CPU or peak-RSS comparison: child-process sampling is Linux-only and was
  N/A on Windows.
- This benchmark used native services, not `docker-compose.lab.yml`; compose
  reproducibility still requires Docker.

## Artifacts

- `dist/native-lab-standard-final/report.json` and `summary.md`
- `dist/native-lab-deep-final/report.json` and `summary.md`
- manifests: git `6c8bebee2710991e4d061e63fb249d8dc19da987` (dirty), Go
  `1.27.2 windows/amd64`
- standard binary SHA-256
  `35dc07e430c4b2bfaff9fe87efe4913411f5012cf91de0b3125e0eb1609689b5`
- deep binary SHA-256
  `e567e91a698d9116fa453c544491500aad9c3fb58c87810a399ee178ad876f63`
- live dataset SHA-256 (session-specific): standard
  `50ea7f99200e6ca290b5a8aecf1eca4d7f0aef467098548fadd74a5dba4507a6`;
  deep `3456955b6b9db6d5c8d94a9fc7f9d08c48ad15df222cd7afe9e28b4b61a373c4`
- checked-in template: `bench/datasets/native-lab.yaml`, SHA-256
  `f310f850a2e5719afb3238c6d15a5e539d74c00193b6e9624b240837609da12e`
  (placeholder sessions; never commit live cookies)
- temporary live datasets are intentionally outside the repository and are
  not evidence suitable for publication without redaction.

## Reproduce

```sh
go build -o dist/gash.exe ./cmd/gash
go build -tags deep -o dist/gash-deep.exe ./cmd/gash
go run ./cmd/gash bench validate bench/datasets/native-lab.yaml

dist/gash-deep.exe bench run --dataset <live-native-lab.yaml> \
  --tool gash,nuclei --gash-bin dist/gash.exe \
  --nuclei-bin <nuclei.exe> --out dist/native-lab-standard-final

dist/gash-deep.exe bench run --dataset <live-native-lab-deep.yaml> \
  --tool gash,nuclei --gash-bin dist/gash-deep.exe \
  --nuclei-bin <nuclei.exe> --out dist/native-lab-deep-final
```

Replace the placeholder sessions in the checked-in dataset with fresh DVWA
`PHPSESSID` values locally; never commit them.
