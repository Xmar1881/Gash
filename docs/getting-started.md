# Getting Started with Gash

> A hands-on tutorial for running your first scans, understanding findings,
> and extending Gash with custom plugins.

---

## Prerequisites

- **Go 1.27+** (toolchain `go1.27.3`) — [download](https://go.dev/dl/)
- **Git** — for cloning the repo
- **Chrome/Chromium** (optional) — required for `--browser-verify` deep scans

Verify installation:

```sh
go version
# go version go1.27.3 ...
git --version
```

---

## 1. Clone and Build

```sh
git clone https://github.com/Xmar1881/Gash.git
cd Gash
go test ./...          # run all tests (takes ~2 min)
go build -o gash ./cmd/gash
./gash --help
```

You should see the main help output with subcommands: `menu`, `scan`, `plugins`, `bench`, `openapi`, `diff`, and `suppress`.

For an interactive menu with a command console, run:

```sh
./gash menu
# or simply ./gash in a terminal
```

---

## 2. Run the Fixture Lab (Safe Sandbox)

Gash includes a built-in vulnerable lab for safe testing:

```sh
# Start the lab in background
go run ./cmd/gash bench lab up
# Lab runs at http://127.0.0.1:<random-port>
# URL is printed to stdout; note it down
```

Or run a one-shot scan against the lab:

```sh
# Standard profile (no browser)
go run ./cmd/gash bench run --dataset bench/datasets/fixtures.yaml --no-browser-verify

# Deep profile (requires Chrome, takes ~7 min)
go run -tags deep ./cmd/gash bench run --dataset bench/datasets/fixtures-deep.yaml
```

This produces a report in `dist/bench-results-<timestamp>/` with:
- `summary.md` — TP/FP/TN/FN, precision, recall, F1
- `findings.csv` — every finding with evidence
- `report.html` — human-readable report

---

## 3. Your First Scan

Scan a local target you own (e.g., a dev server):

```sh
# Passive scan (safe default)
./gash scan --target http://localhost:8080 --scope localhost

# Active scan (requires --active)
./gash scan --target http://localhost:8080 --scope localhost --active

# Deep scan with browser verification (requires Chrome)
./gash scan --target http://localhost:8080 --scope localhost --profile deep --browser-verify
```

### Output Formats

```sh
# JSON (for CI/SIEM)
./gash scan --target ... --format json --output report.json

# SARIF 2.1.0 (GitHub Code Scanning)
./gash scan --target ... --format sarif --output report.sarif

# HTML (human-readable)
./gash scan --target ... --format html --output report.html
```

---

## 4. Understanding Findings

Every finding includes:

```json
{
  "id": "finding_abc123",
  "rule_id": "GASH-001",
  "cwe": "CWE-79",
  "title": "Reflected XSS (basic contexts)",
  "severity": "high",
  "confidence": "static-execution-evidence",
  "target": "http://example.com/search?q=test",
  "plugin_id": "xss-reflected-basic",
  "evidence": {
    "canary": "gash_js_24",
    "context": "url-executable",
    "execution": "static",
    "control_result": "clean"
  }
}
```

### Confidence Levels

| Level | Meaning |
|-------|---------|
| `tentative` | Signal present but insufficient for proof (e.g., reflection without execution context) |
| `firm` | Strong signal with control comparison (e.g., error signature absent in control) |
| `static-execution-evidence` | Parser-recognized execution payload + clean control |
| `confirmed` | Browser-verified execution + clean control (deep build only) |
| `blocked` | WAF/block page detected — evidence suppressed |
| `unverified` | Plugin ran but could not reach oracle decision |

---

## 5. Exploring Plugins

List all built-in plugins:

```sh
./gash plugins list
```

Validate a plugin YAML/JS:

```sh
./gash plugins validate plugins/xss/xss-reflected-basic.js
```

Run plugin fixture tests:

```sh
./gash plugins test plugins/xss/xss-reflected-basic.js
```

### Plugin Anatomy (Tier 1 YAML)

```yaml
id: my-xss-check          # unique ID
name: My XSS Check
description: Detects reflected XSS in search parameter
severity: high
tags: [xss, reflected]
safe: true                # passive by default
deep: false               # not browser-dependent
active: false             # no state-changing requests
phase: probe              # probe | active | exploit
order: 50                 # execution order
api_version: "1.0"
tests: tests/fixtures/my-xss-check/
request:
  method: GET
  param_names: [q, search, query]
  payload: '"><script>alert(1)</script>'
oracle:
  name: reflection
  params:
    contexts: [html-text, html-attr, js-string, url-attr]
```

---

## 6. Creating Your First Plugin

### Option A: Scaffold a Tier 1 YAML Plugin

```sh
./gash plugins new my-check --tier yaml
# Creates my-check.yaml in current directory
```

Edit `my-check.yaml`, then validate and test:

```sh
./gash plugins validate my-check.yaml
./gash plugins test my-check.yaml
```

### Option B: Scaffold a Tier 2 JavaScript Plugin

```sh
./gash plugins new my-advanced-check --tier js
# Creates my-advanced-check.js with execution bindings
```

### Option C: Use a Template

```sh
cp templates/template.yaml my-check.yaml
# Edit my-check.yaml
```

---

## 7. Running in CI/CD

### GitHub Actions Example

```yaml
# .github/workflows/scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - name: Build Gash
        run: go build -o gash ./cmd/gash
      - name: Scan
        run: |
          ./gash scan \
            --target https://staging.example.com \
            --scope staging.example.com \
            --profile standard \
            --format sarif \
            --output gash.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: gash.sarif
```

### Fail-on Gates

```sh
# Fail if any firm+ finding
./gash scan --target ... --fail-on firm

# Fail if precision drops below 0.99 (requires benchmark baseline)
./gash bench run --dataset bench/datasets/fixtures.yaml --fail-on-regression
```

---

## 8. Next Steps

- **Read the architecture**: `docs/architecture.md`
- **Learn plugin development**: `docs/plugin-development.md`
- **Understand evidence standards**: `docs/evidence-standard.md`
- **Run the benchmark**: `docs/benchmark.md`
- **See known limits**: `docs/known-limits.md`
- **Browse reference plugins**: `plugins/README.md`
- **Check metrics**: `docs/metrics/README.md`

---

## 9. Common Issues

| Problem | Solution |
|---------|----------|
| `go: cannot find main module` | Run from repo root (`cd Gash`) |
| `chromedp: executable not found` | Install Chrome/Chromium; ensure in PATH |
| `oob-not-configured` findings | Provide `--oob-server https://your.interactsh.server` |
| Scan hangs | Reduce `--max-requests-total`, check `--rate-limit` |
| No findings on known vuln | Verify `--scope` includes target; check plugin `active`/`safe` flags |

---

## 10. Getting Help

- **Support guide**: [SUPPORT.md](../SUPPORT.md)
- **Issues**: [github.com/Xmar1881/Gash/issues](https://github.com/Xmar1881/Gash/issues)
- **Security**: [Private advisory](https://github.com/Xmar1881/Gash/security/advisories/new)

---

*Happy scanning! Remember: only scan targets you own or have explicit written permission to test.*