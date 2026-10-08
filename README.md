# GASH // Vulnerability & Penetration Engine

> Türkçe sürüm için: [README.tr.md](README.tr.md)

> Fast, modular automated web vulnerability scanner + pentest engine.
>
> Positioning: a **heuristic security smoke scanner** — one command from recon
> to report. It does not replace ZAP/Nuclei/manual pentesting; it finds the
> obvious fast so humans can spend time on the subtle.

[![GASH CI](https://github.com/Xmar1881/Gash/actions/workflows/ci.yml/badge.svg)](https://github.com/Xmar1881/Gash/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12%20%7C%203.13-blue)
![License](https://img.shields.io/badge/license-Apache--2.0-green)
![Version](https://img.shields.io/badge/version-0.5.0-red)

```text
  ██████╗  █████╗ ███████╗██╗  ██╗
 ██╔════╝ ██╔══██╗██╔════╝██║  ██║
 ██║  ███╗███████║███████╗███████║
 ██║   ██║██╔══██║╚════██║██╔══██║
 ╚██████╔╝██║  ██║███████║██║  ██║
  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
  [ GASH // Vulnerability & Penetration Engine ]
  v0.5.0  //  fast | modular | thorough
```

> [!WARNING]
> **Authorized / legal testing only.** Unauthorized scanning is a crime. You are responsible for how you use it.

---

## Why GASH?

- **Full scan in one command:** recon + crawl + 44 security checks + report
  (vulnerability detection, attack-surface discovery and config auditing)
- **Smart:** picks wordlists from tech fingerprint (WordPress / PHP / Node / Java / Python)
- **Modern-web aware:** the misconfigs AI-built sites ship with — missing
  headers, wildcard CORS, open redirects, traversal, risky methods, and
  secrets hardcoded in JS bundles
- **Crawler included:** extracts links + forms + `sitemap.xml` + Swagger/OpenAPI + API endpoints from JS (+ opt-in `--spa` headless runtime pass for JS-heavy apps)
- **Reporting:** terminal table + `JSON / HTML / TXT / SARIF / XML` + diff against previous scan (**NEW/FIXED** tracking)
- **Honest output:** discovery (admin pages, robots.txt, reachable dirs) is
  reported as unscored `INFO` observations — a found `/login` page is never
  a CRITICAL
- **Bulk mode:** scan a target list with `--resume` support
- **Plugin:** a new check is one decorator (`core/registry.py`)

## Quick Start

```bash
git clone https://github.com/Xmar1881/Gash.git
cd Gash

# install (Windows: `py`, Linux/macOS: `python3`)
py -m pip install -r requirements.txt
# or: pip install -e .   (provides the `gash` command)

# full scan (safe defaults: no time-based, no active POST/uploads/logins)
py gash.py -t https://target.com --full

# deep scan (opt-in: time-based + active POST + upload-rce + login tests)
py gash.py -t https://target.com --full --deep

# interactive scan wizard (no commands to memorize)
py gash.py --menu

# with report
py gash.py -t https://target.com --full -o report.html -v
```

Optional (only for `--dom` headless DOM XSS verification):

```bash
py -m pip install playwright
py -m playwright install chromium
```

## Usage

| Command | What it does |
|---|---|
| `py gash.py -t URL --full` | Recon + Scan (default) |
| `py gash.py -t URL --recon` | Recon only: IP / DNS / ports / headers / server |
| `py gash.py -t URL --scan` | Vulnerability scan only |
| `py gash.py -t URL --scan --quick` | Fast mode: skips time-based + active POST probes |
| `py gash.py -t URL --full --deep` | Deep mode (opt-in): time-based + active POST + upload-rce + login tests |
| `py gash.py -t URL --full --scope a.com,api.a.com` | Scope allowlist: refuse out-of-scope targets |
| `py gash.py -t URL --full --fail-on critical` | CI gate: exit 3 when CRITICAL findings exist (`medium` also works) |
| `py gash.py -t URL --full --no-color` | Plain output (CI logs) |
| `py gash.py -t URL --full --proxy http://127.0.0.1:8080` | Route traffic via Burp/ZAP |
| `py gash.py -t URL --full --user-agent "MyScanner/1.0"` | Custom User-Agent |
| `py gash.py -t https://host/app --full` | Sub-app scope: the path is kept (`/app` stays `/app`) |
| `py gash.py -t URL --full --insecure` | Skip TLS verification (self-signed labs only) |
| `py gash.py --list-checks` | List the 44 checks |
| `py gash.py -t URL --full --skip-checks sqli-blind,ssti` | Disable unwanted checks |
| `py gash.py -t URL --full --cookie "session=abc" --header "Authorization: Bearer X"` | Authenticated scan |
| `py gash.py -t URL --full --cookie "a=1" --cookie-b "b=2"` | Cross-session IDOR confirmation with a second user |
| `py gash.py -t URL --full --login-user admin --login-pass 1234` | Try auto-login, scan with session |
| `py gash.py -t URL --full --max-pages 15 --depth 3` | Larger crawler |
| `py gash.py -t URL --full --profile thorough` | Coverage profile: quick / balanced (default) / thorough |
| `py gash.py -t URL --full --dom` | Verify DOM XSS with headless Chromium (slow) |
| `py gash.py -t URL --full --spa --max-xss-urls 40` | SPA runtime discovery (JS routes/forms/API) + larger XSS pool |
| `py gash.py -t URL --full --browser-discovery` | Full browser traffic profile (requests/WS/SSE/routes) into the pool |
| `py gash.py -t http://127.0.0.1:8000 --full` | Local audit auto-runs for loopback targets (read-only; `--local` forces it) |
| `py gash.py -t URL --full --blind-callback abc.interact.sh` | Enable Blind XSS canary placement |
| `py gash.py -t URL --full --oob` | Auto out-of-band verify (Blind XSS + SSRF) via interactsh |
| `py gash.py -t URL --full --delay 0.2 --max-requests 500` | Polite / budgeted scan |
| `py gash.py --target-file targets.txt --full --output-dir reports/` | Bulk scan (per-target report + `bulk_summary.json`) |
| `py gash.py --target-file targets.txt --full --output-dir reports/ --resume` | Resume (skip targets that already have reports) |

`targets.txt` format: one target per line, `#` comments and blank lines are skipped.

## Checks (44)

Output of `py gash.py --list-checks`:

| Name | Description |
|---|---|
| `sqli-error` | Error-based SQLi (DB error signature) |
| `xss-reflected` | Reflected XSS (context-aware + breakout check) |
| `xss-errpage` | 404 + header reflection |
| `upload-form` | Upload form detection (passive) |
| `robots` | robots.txt + Disallow harvesting |
| `smart-dirs` | Smart dir-brute (tech wordlist) |
| `smart-recurse` | Recurse under found paths + backup extensions |
| `sqli-blind` | Boolean-blind + encoding bypass + time-based |
| `ssti` | SSTI template injection |
| `ssrf` | SSRF cloud metadata + surface note |
| `idor` | IDOR/BOLA API object differential |
| `idor-param` | IDOR query parameter (`?id=`, uuid-aware) |
| `authz-matrix` | Anonymous vs user authorization matrix |
| `protopollution` | Prototype Pollution reflection surface |
| `stored-xss` | Stored XSS canary + second-order render check |
| `sqli-login` | Login form SQLi auth-bypass differential `[deep]` |
| `waf-detect` | WAF fingerprint (passive) |
| `cookie-flags` | Cookie HttpOnly/Secure/SameSite audit |
| `upload-rce` | Upload filter bypass (benign content) `[deep]` |
| `smart-tech` | Tech fingerprint + targeted paths |
| `dom-xss` | DOM XSS headless verification, sinks + sources + oracle (`--dom`) |
| `security-headers` | Missing security headers (passive) |
| `open-redirect` | Open redirect via next/redirect params |
| `path-traversal` | Path traversal via file/page params |
| `cors` | Permissive CORS policy (evil origin probe) |
| `http-methods` | Risky HTTP methods (TRACE/PUT/DELETE) |
| `js-secrets` | Hardcoded secrets in JavaScript |
| `jwt-none` | JWTs using alg:none (passive) |
| `graphql-introspection` | GraphQL introspection + schema analysis |
| `host-header` | Host header reflected (cache-poison surface) |
| `security-txt` | security.txt presence (RFC 9116) |
| `os-command-injection` | OS command injection via `;id`/`\|id` |
| `crlf-injection` | CRLF header injection probe |
| `csrf-surface` | POST forms without anti-CSRF controls |
| `firebase-open` | Public Firebase realtime database |
| `supabase-anon` | Supabase table readable without login |
| `nextjs-middleware-bypass` | Next.js middleware auth bypass |
| `wp-user-enum` | WordPress username disclosure |
| `swagger-exposed` | Public API docs (Swagger/OpenAPI) |
| `mass-assignment` | Client-controllable role field |
| `tls-audit` | TLS certificate + protocol audit |
| `login-enum` | Login username enumeration |
| `ldap-injection` | LDAP wildcard auth bypass |
| `cache-poisoning` | Cache poisoning via Host reflection |

Every finding is enriched with `CWE + OWASP Top 10 + estimated CVSS + remediation`
(`core/knowledge.py`) and carries a `confidence` rating (High/Medium/Low) set
by the check that produced it.

Blind XSS notes are only produced when `--blind-callback` points to an external
listener you control — no listener, no noise.

## Out-of-band verification

With `--oob`, every Blind XSS and SSRF probe gets a unique subdomain on an
interactsh server (default `https://interact.sh`, or `--oob-server` for your
own). Callbacks upgrade guesses into proof: **"Blind XSS (confirmed via
OOB)"** and **"SSRF (confirmed via OOB)"**. No callback means no finding.
`--oob-wait` caps the wait (default 20s). Needs `pip install gash[oob]`
(`cryptography`); without it the scan continues OOB-less with a warning.

## Safety Model

Scans are **safe by default**: no time-based delays, no active POST
submissions, no file uploads, no login attempts. These run only with an
explicit `--deep` (the wizard asks for it). Stored-XSS probes never touch
password/hidden fields, and upload probes are always benign text.
JSON/XML/GraphQL body and PUT/PATCH/DELETE mutations are likewise
deep-only and structure-preserving (one leaf value at a time); safe mode
never mutates request bodies.
TLS certificates are verified by default (`--insecure` opts out loudly).
Severity labels in output are `CRITICAL/MEDIUM/LOW` plus unscored `INFO`
observations; CLI messages are English.
Check failures are never silent: a crashed check prints one line, the rest
keep running, and the scan ends as **SCAN DEGRADED** (terminal + all report
formats) instead of "Clean". Per-check status (passed/findings/skipped/error)
ships in the report under `scan_health`.

## Limitations

Honest scope, compared to Nuclei/ZAP/sqlmap:

- **Scanner, not exploiter:** no payload execution, no session hijacking.
- IDOR findings are single-session heuristics unless a second session
  (`--cookie-b`) or anonymous access proves them (titles say so).
- CVSS scores and the 0–100 risk score are **static estimates per finding
  class**, not environment-aware calculations.
- OOB verification is opt-in — `--oob` (interactsh) covers Blind XSS/SSRF
  callbacks; without a listener there are no blind findings by design.
- No checks yet for: XXE, HTTP/3 audit, certificate chain-of-trust,
  WebSocket message fuzzing, JWT acceptance replay.

## Report Example

```bash
py gash.py -t https://target.com --full -o report.html
# report.json / report.txt / report.sarif / report.xml work too (by extension)
```

- **Terminal:** colored severity list + summary table (CRITICAL / MEDIUM / LOW)
- **HTML:** severity distribution, risk score (0-100), category breakdown, executive summary, filter buttons, `evidence` inside `<details>`
- **SARIF / JUnit:** `report.sarif` (code-scanning ingestion) and `report.xml` (CI test gateways)
- **Diff:** every scan is stored under `.gash_history/`; the next scan shows `X NEW / Y FIXED`

## Project Structure

```text
Gash/
├── gash.py              # entry point (CLI -> recon/scan -> report)
├── core/
│   ├── cli.py           # argparse flags
│   ├── recon.py         # IP / DNS / ports / headers
│   ├── scanner.py       # SQLi / XSS / dir-brute engine
│   ├── advanced.py      # blind / SSTI / SSRF / IDOR / upload-RCE ...
│   ├── bulk.py          # bulk scan helpers
│   ├── crawler.py       # BFS crawler (sitemap + swagger + JS)
│   ├── discovery.py     # unified discovery: canonicalize, JS/API/REST, profiles
│   ├── api_params.py    # recursive body params (JSON/XML/GraphQL) + safe mutate
│   ├── diff.py          # baseline/differential engine (all checks share it)
│   ├── xss_context.py   # reflection context analysis
│   ├── xss_payloads.py  # context-aware payload generator
│   ├── xss_spa.py       # SPA runtime discovery (--spa)
│   ├── domxss.py        # Playwright DOM verification (--dom)
│   ├── authz.py         # IDOR/BOLA + authorization matrix engine
│   ├── graphql.py       # GraphQL schema analysis
│   ├── localaudit.py    # local machine profile (--local)
│   ├── reporter.py      # terminal + json/html/txt/sarif/xml + diff
│   ├── knowledge.py     # CWE / OWASP / CVSS / remediation
│   ├── registry.py      # plugin system (@check)
│   ├── net.py           # delay / budget / auth
│   ├── menu.py          # interactive scan wizard
│   └── banner.py        # ASCII banner
├── tests/
│   ├── test_unit.py         # no network needed
│   ├── test_bulk.py         # bulk scan (no network)
│   ├── test_lab.py          # local lab regression (~25s)
│   └── test_integration.py  # local stub server (~15s)
├── bench/
│   ├── lab.py               # vulnerable lab app (stdlib only)
│   └── run_bench.py         # DVWA/Juice Shop precision/recall
└── .github/workflows/ci.yml  # ubuntu+windows × 3.12/3.13
```

Adding a new check:

```python
from core.registry import check

@check("my-check", "Description", order=10)
def test_mine(session, urls, timeout, verbose=False):
    return []  # list[Finding]
```

## Tests

```bash
py -m pytest tests/ -q
py -m ruff check core gash.py tests
py -m bandit -q -ll -r core gash.py
py -m pip_audit -r requirements.txt
```

CI (ubuntu+windows × 3.12/3.13) runs all of the above, then installs the
package and smoke-tests the `gash` entry point.

## Benchmark

XSS precision/recall against DVWA + Juice Shop (opt-in, live targets —
never in CI):

```bash
docker compose -f bench/docker-compose.yml up -d
py bench/run_bench.py --target all --deep --dom --json-out bench/results.json
```

Ground truth in `bench/cases_*.json` (vulnerable endpoints + negative
controls). Scoring counts **confirmed** titles toward recall/precision
and reports unconfirmed/suspected separately (honesty stats).

## Roadmap

- [x] Bulk scan (`--target-file` + resume)
- [x] Safe-by-default + `--deep` opt-in + `--scope` + `--fail-on`
- [ ] YAML profiles (quiet / thorough)
- [x] Blind-XSS/OOB verification (`--oob` via interactsh, silent without)
- [ ] CVE mapping (version → known vulnerability)
- [x] SARIF / JUnit outputs
- [ ] Webhook notifications
- [x] Modern check classes: traversal, open redirect, CORS, security headers,
  risky methods, JS secrets

## Contributing

PRs and issues welcome. Please:

1. Keep `py -m pytest tests/ -q` green
2. Add a unit test for new checks
3. No destructive payloads — benign proof only

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Author

Developed by **[Xmar1881](https://github.com/Xmar1881)**.
