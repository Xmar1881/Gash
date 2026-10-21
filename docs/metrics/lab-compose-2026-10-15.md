<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/lab-compose-2026-10-15.md
What: Compose-lab recall procedure and BLOCKED status without a docker runtime.
Why: DVWA/Juice Shop/WebGoat recall stays unmeasured where docker is absent; the
procedure is filed so any docker host can reproduce it byte-identical.
-->

# Lab: compose DVWA / Juice Shop / WebGoat (2026-10-15, BLOCKED)

## Status

BLOCKED — no docker runtime in this environment (`docker --version` fails:
`docker : The term 'docker' is not recognized...`, PowerShell
`CommandNotFoundException`; re-verified 2026-10-15 during the 5-job run,
toolchain go1.27.2). No compose service was started, no `--aggressive`
scan was run against DVWA, Juice Shop, or WebGoat, and no recall number is
claimed. At that date the localhost synthetic lab
(`lab-aggressive-local-2026-10-14.md`) was the only measured recall; the
2026-10-20 native lab later added the full three-application run
(`native-lab-2026-10-20.md`). Sahte lab sonucu YOKTUR. Procedure below
re-verified against current CLI
(`scan --aggressive` plus `--scope` exist) and current compose pins
(DVWA 2.0 / Juice Shop 17.1.0 / WebGoat 2023.8, 127.0.0.1:8081-8083).

## Pinned Lab

`docker-compose.lab.yml` (repo root, localhost-only, Kırmızı çizgi: SADECE
localhost lab, `--scope` zorunlu):

- `dvwa`: `vulnerables/web-dvwa:2.0` on `127.0.0.1:8081:80`
- `juiceshop`: `bkimminich/juice-shop:17.1.0` on `127.0.0.1:8082:3000`
- `webgoat`: `webgoat/webgoat:2023.8` on `127.0.0.1:8083:8080`
- Network `gash-lab` internal; no `latest` tag anywhere.

## Reproduction Procedure (docker host, adım adım)

Only on targets you own or have explicit written permission to test; the
compose lab is localhost-only by design. Kırmızı çizgi: izinli/localhost
dışı hedef YOK, her taramada `--scope 127.0.0.1` zorunlu.

1. Ön koşul kontrolü (kanıt olarak çıktıyı sakla):

   ```sh
   docker --version
   docker compose version
   ```

2. Lab'ı kaldır (pinned compose, arka plan):

   ```sh
   docker compose -f docker-compose.lab.yml up -d
   docker compose -f docker-compose.lab.yml ps
   curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8081/
   curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8082/
   curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8083/WebGoat/
   ```

   Beklenen: üç servis `Up`, üç health check HTTP 200 (WebGoat ilk açılışı
   yavaş olabilir; `docker compose logs webgoat` ile hazır olmasını bekle).

3. Agresif tara (SADECE localhost lab, `--aggressive` + `--scope`):

   ```sh
   go run ./cmd/gash scan --target http://127.0.0.1:8081 --scope 127.0.0.1 --aggressive --format json --output lab-dvwa.json
   go run ./cmd/gash scan --target http://127.0.0.1:8082 --scope 127.0.0.1 --aggressive --format json --output lab-juiceshop.json
   go run ./cmd/gash scan --target http://127.0.0.1:8083/WebGoat --scope 127.0.0.1 --aggressive --format json --output lab-webgoat.json
   ```

   Not: `--aggressive` tek bayrakla `active+deep` ve yüksek bütçeyi açar;
   `--scope 127.0.0.1` olmadan scope dışı gerekçesiyle çalıştırma.

4. Sonuçları say (hangi metriklerin doldurulacağı):

   - Her hedef için `lab-<hedef>.json` içindeki findings'leri sınıfa göre
     say: DVWA'da SQLi, XSS, command injection; Juice Shop'ta injection,
     auth, misconfig; WebGoat'ta ilgili ders sınıfları.
   - `## Precision` bölümüne: TP/FP sayımı + Precision = TP/(TP+FP).
   - `## Recall` bölümüne: bilinen/seeded zafiyetlere karşı TP/FN +
     Recall = TP/(TP+FN). Seed listesi docker imaj + sürümle birlikte
     sabitlenmeli (imaj digest `docker images --digests` çıktısıyla).
   - `## Corpus` bölümüne: `TestB4CorpusZeroFirmPlus` çıktısı (0 `firm`
     plus beklenir).
   - `## Gate Verdict` bölümüne: Precision >= 0.99 ise PASS, değilse FAIL +
     gerekçe.
   - `## Dataset` bölümüne: compose digest'leri + üç JSON artefact yolu +
     `Dataset hash` (JSON'ların sha256 listesi).

5. Lab'ı indir:

   ```sh
   docker compose -f docker-compose.lab.yml down
   ```

6. Raporu dosya: bu dosyanın `Unmeasured (BLOCKED)` satırlarını ölçümlerle
   değiştirip `docs/metrics/README.md` Lab Reports tablosuna bağla.

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

- Compose file: `docker-compose.lab.yml` (pinned: DVWA 2.0, Juice Shop 17.1.0,
  WebGoat 2023.8; digest'ler docker host'ta `docker images --digests` ile
  kilitlenecek).
- Scan artifacts: none (no run).

## Update (2026-10-20): docker-free Juice Shop subset measured

**Superseded by the full native lab.** The two-scenario Juice Shop subset
below was the first Docker-free measurement; the later 22-scenario run added
DVWA and WebGoat, fixed the prefix-dependent SQLi corpus, and measured deep
DOM XSS. Final results: Gash standard `TP=11 FP=0 TN=9 FN=2`, deep
`TP=12 FP=0 TN=9 FN=1`, Nuclei `TP=5 FP=0 TN=9 FN=8`. See
`native-lab-2026-10-20.md`. The compose procedure itself is still blocked.

Docker is still absent, but Juice Shop 17.1.0 can be served natively: the
official release archive `juice-shop-17.1.0_node22_win32_x64.zip` was
downloaded from GitHub, MD5-verified against the published
`86cbaaf822177e1b1f77930a34301326`, extracted, and run with local Node
v22.14.0 on `127.0.0.1:8082`. At the time of this subset DVWA (no PHP) and
WebGoat 2023.8 (needed Java 17) were not yet available; both were added for
the later full native lab (`native-lab-2026-10-20.md`).

A temporary compose-kind dataset with exactly the two, pinned Juice Shop
scenarios from `bench/datasets/compose-lab.yaml` (sqli-search, dom-search)
ran with the deep binary. Both scenarios were independently verified as
vulnerable, then scored:

| tool | sqli-search | dom-search | findings | duration |
|---|---|---|---|---|
| gash (standard profile) | FN | FN | 1 unmatched (CORS preflight) | 45s |
| nuclei v3.11.1 (same tags) | FN | FN | 2 unmatched (swagger, prometheus) | 3m35s |

This subset has no clean/trap scenarios, so precision is N/A; the table
measures recall only (0/2 for both tools). Out-of-scope findings are listed
by the harness, not scored. Artifacts (local, gitignored):
`dist/bench-juiceshop-native3`, `dist/bench-juiceshop-native-compare`.

### Why gash missed both (reproduced, not harness noise)

- `juiceshop-sqli-search`: a direct scan of
  `/rest/products/search?q=apple` also produced no SQLi finding, so endpoint
  discovery is not the cause. Juice Shop v17 returns 200 for `q='` but 500
  with `SQLITE_ERROR ... syntax error` only when the value keeps a prefix
  (`q=apple'`). The error-based payload corpus probes value replacements and
  therefore never sees the SQLite error on this route.
- `juiceshop-xss-dom-search`: the DOM XSS lives in the Angular search route;
  the standard profile has no browser crawl and `dom-sink-basic` needs static
  source-to-sink evidence on the rendered surface, so no finding is produced.
  This stays an honest recall gap on real SPA applications.

### Verification-definition corrections (dataset, not scoring)

Running against the real app exposed two unexercised definitions in
`compose-lab.yaml`; both were corrected to match measured v17.1.0 behavior:
the SQLi `http-error` payload is now `apple'` with
`expect_contains: ["SQLITE_ERROR", "syntax error"]` (the actual signature),
and the DOM `browser-exec` payload now uses the documented alert form
(`<iframe src="javascript:alert(...)">`); the previous marker-only payload
set `window.__gashCanary` inside the iframe while the verifier probes the
top window. Verification remains independent (HTTP error signature / real
browser execution); no expected value or label was relaxed.
