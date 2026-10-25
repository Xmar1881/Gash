# Frequently Asked Questions

## General

### What is Gash?

Gash is a Go-native, plugin-driven web security scanner. Its core philosophy: **plugins propose candidates; engine-owned oracles decide findings**. No plugin can mint a finding without engine-grade evidence (control comparison, repeat rules, baseline gating).

### How is Gash different from Nuclei/ZAP/Burp?

| Aspect | Gash | Nuclei | ZAP | Burp |
|--------|------|--------|-----|------|
| **Finding authority** | Engine oracles only | Template matchers | Scan rules + alerts | Scanner + analyst |
| **Plugin model** | Drop-in YAML/JS/native | YAML templates | Add-ons/scripts | BApp extensions |
| **False-positive discipline** | Corpus gate (precision ≥ 0.99) | Community QA | Risk/confidence taxonomy | Manual verification |
| **OOB** | Self-hosted only, honest skip | Interactsh (public OK) | Add-ons | Collaborator (SaaS) |
| **License** | AGPL-3.0-only | MIT/BSD | Apache 2.0 | Commercial |

### Is Gash production-ready?

**Experimental** (`v0.1.0-dev`). The core architecture is stable but:
- Plugin set is growing (283 reference plugins)
- Real-world recall is manually measured on lab targets only
- Deep build (browser) requires Chrome/Chromium
- API may change before `v1.0.0`

Use for: CI security gates, internal assessments, plugin development.
Avoid for: Unsupervised production scanning, compliance reports requiring mature tooling.

---

## Installation & Build

### Why does `go build` fail with "sync imported and not used"?

Fixed in `go1.27.3` (toolchain update). Run:

```sh
go mod tidy
go build ./...
```

### Do I need CGO?

**No.** `CGO_ENABLED=0` is recommended for static binaries. Only the deep build (`-tags deep`) uses `chromedp` which requires CGO for ChromeDP.

### Can I cross-compile?

Yes:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o gash-linux-amd64 ./cmd/gash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o gash-windows-amd64.exe ./cmd/gash
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o gash-darwin-arm64 ./cmd/gash
```

---

## Scanning

### Why am I getting no findings on a known vulnerable target?

Common causes:

1. **Scope**: Target not in `--scope` (default allows all, but cross-host redirects followed)
2. **Profile**: Using `safe` (default) — passive only. Try `--active` or `--profile deep`
3. **Plugin not loaded**: Check `./gash plugins list | grep <plugin-id>`
4. **OOB not configured**: Blind plugins (`*_oob`, `*_timing`) require `--oob-server`
5. **Rate limit too low**: Increase `--rate-limit` and `--max-requests-total`

### What does `--scope` actually do?

Without `--scope`: **open mode** — follows all redirects/crawl links (any host, any scheme).
With `--scope example.com`:
- Only requests to `example.com` and subdomains allowed
- Redirects to outside scope are blocked
- DNS rebinding protection (pinning)
- HTTP→HTTPS upgrade only, never downgrade

### How do I scan a target behind login?

Option 1: **Cookie** (simplest)
```sh
./gash scan --target https://app.example.com --cookie "session=abc123"
```

Option 2: **Login automation** (form-based)
```sh
./gash scan --target https://app.example.com \
  --login-url https://app.example.com/login \
  --login-user admin \
  --login-pass-env GASH_LOGIN_PASS
```

Option 3: **Auth header** (API)
```sh
./gash scan --target https://api.example.com \
  --auth-header "Authorization: Bearer <token>"
```

### Can I scan multiple targets at once?

```sh
# From file (one URL per line)
./gash scan --target-file targets.txt --scope example.com

# Resume interrupted bulk scan
./gash scan --target-file targets.txt --resume
```

---

## Plugins

### How do I write a custom plugin?

1. **Scaffold**: `./gash plugins new my-check --tier yaml`
2. **Edit** the generated YAML
3. **Validate**: `./gash plugins validate my-check.yaml`
4. **Test**: `./gash plugins test my-check.yaml` (needs fixtures in `tests/fixtures/my-check/`)
5. **Drop in**: `~/.gash/plugins/` or `GASH_PLUGIN_PATH`

See: `docs/plugin-development.md`, `docs/yaml-plugin-spec.md`, `templates/README.md`

### What's the difference between Tier 1, 2, and 3?

| Tier | Format | Sandbox | Trust | Use Case |
|------|--------|---------|-------|----------|
| 1 | YAML (declarative) | None | Auto-discovered | Most detectors (header, error, redirect, reflection) |
| 2 | JavaScript (ES5+) | goja sandbox | Auto-discovered | Complex logic, timing, browser-verified flows |
| 3 | Native Go (gRPC) | None | **Explicit `gash plugins trust` + SHA256** | High-performance, system access, supply-chain sensitive |

### How do I enable a Tier 3 (native) plugin?

```sh
# 1. Build the plugin binary
go build -o my-native-plugin ./plugins/native/my-plugin

# 2. Trust it (one-time, requires SHA256)
./gash plugins trust ./my-native-plugin --sha256 <hash>

# 3. Run with --strict-plugins to only execute trusted Tier 3
./gash scan --target ... --strict-plugins
```

### Why does my plugin test fail with "precision below 0.99"?

The metric gate (`TestMetricGate`) runs fixture tests and requires:
- Precision ≥ 0.99 (TP / (TP + FP))
- No `firm+` findings on clean corpus

Fix: Add negative fixtures for false-positive cases, tighten oracle params, or adjust `signature_set`.

---

## Evidence & Confidence

### What do the confidence levels mean?

| Level | Oracle Decision | Typical Use |
|-------|-----------------|-------------|
| `tentative` | Signal exists but weak | Reflection without execution context |
| `firm` | Strong differential signal | Error signature absent in control |
| `static-execution-evidence` | Parser-recognized execution + clean control | Static XSS with executable context |
| `confirmed` | Browser-verified trigger + clean control | DOM XSS, stored XSS render (deep build) |
| `blocked` | WAF/block page detected | Evidence suppressed, stats only |
| `unverified` | Plugin ran, no oracle decision | Budget exhausted, plugin error |

### Why is my XSS finding `firm` not `confirmed`?

- **Standard build**: DOM sinks max at `firm` (no headless browser)
- **Deep build + `--browser-verify`**: Upgrades to `confirmed` if headless execution triggers with clean control
- **Fragment/hash routes**: Only browser-verified (not static)

### What is "control comparison"?

For differential/error/timing oracles, Gash sends a **control request** with a neutral payload (e.g., `gash-control-neutral`). The response is compared to the attack response. If the signature appears in both, the finding is **rejected** (not distinguishing).

---

## OOB (Out-of-Band)

### Why are OOB plugins skipping with `oob-not-configured`?

OOB verification is **explicit opt-in**. You must run your own interaction server:

```sh
# Start interactsh server (example)
interactsh-server

# Scan with OOB
./gash scan --target https://example.com --oob-server https://your.interactsh.server
```

Without `--oob-server`, all `oob: required` plugins honestly skip and report `oob-not-configured` in stats.

### Can I use a public Interactsh server?

**No.** Gash requires self-hosted OOB to prevent:
- Callback leakage to third parties
- Uncontrolled correlation windows
- Dependency on external infrastructure

---

## Benchmarking

### How do I run the full benchmark?

```sh
# Standard (no browser, ~1.5 min)
go run ./cmd/gash bench run --dataset bench/datasets/fixtures.yaml --no-browser-verify

# Deep (with browser, ~7 min)
go run -tags deep ./cmd/gash bench run --dataset bench/datasets/fixtures-deep.yaml
```

### What is the regression gate?

`--fail-on-regression` compares current run against `bench/baselines/fixtures.json`:
- Recall drop > 0% → fail
- Duration increase > 50% → fail
- Request increase > 25% → fail
- Precision < 0.99 → fail

Update baseline after intentional changes:
```sh
go run ./cmd/gash bench baseline dist/bench-latest/report.json > bench/baselines/fixtures.json
```

---

## Contributing

### How do I add a new detector?

1. Check `docs/known-limits.md` for gaps
2. Pick the right oracle (reflection, error, differential, timing, oob, execution)
3. Scaffold: `./gash plugins new my-detector --tier yaml`
4. Write fixtures: `tests/fixtures/my-detector/positive/`, `negative/`
5. Run metric gate: `go test ./tests/plugins -run TestMetricGate/my-detector`
6. Update docs: `plugins/README.md`, `docs/detector-inventory.md`, `docs/metrics/my-detector.md`
7. Open PR with template filled

### What makes a good plugin contribution?

- Uses **existing oracles** (no new oracle code)
- Includes **positive, negative, and ambiguous fixtures**
- Honest confidence (no `confirmed` without control)
- Safe defaults (`safe: true`, `active: false`)
- Passes `go test ./...` and `go vet ./...`

---

## Troubleshooting

### Scan is slow / hangs

```sh
# Reduce budgets
./gash scan --target ... --max-requests-total 1000 --max-requests-per-target 100 --rate-limit 5

# Disable aggressive features
./gash scan --target ... --profile standard  # not deep/aggressive
```

### Memory usage high

```sh
# Limit response body storage
./gash scan --target ... --max-response-bytes 1048576  # 1 MB
```

### Plugin not discovered

- Check file extension: `.yaml` or `.js` (not `.yml`)
- Check location: `~/.gash/plugins/` or `GASH_PLUGIN_PATH`
- Check syntax: `./gash plugins validate path/to/plugin.yaml`
- Check `id` uniqueness: no duplicate IDs in registry

### Certificate/TLS errors

```sh
# Skip TLS verify (dev only)
./gash scan --target https://self-signed.example.com --tls-insecure

# Custom CA
./gash scan --target https://internal.example.com --ca-cert /path/to/ca.pem
```

---

## Legal & Ethics

### Can I scan any website?

**No.** Only scan systems you **own** or have **explicit written permission** to test. Unauthorized scanning may violate:
- US CFAA (18 U.S.C. § 1030)
- UK Computer Misuse Act 1990
- Turkish Penal Code Article 243/244
- EU Directive 2013/40/EU

### Does Gash phone home?

**No.** Zero telemetry, zero external calls unless you configure:
- `--oob-server` (your server)
- `--proxy` (your proxy)
- `--scope` DNS resolution (target hosts only)

### Can I use Gash commercially?

Yes, under AGPL-3.0-only. If you **modify and distribute** Gash (or offer it as a network service), you must provide source code to users. See `COPYING` for full license + third-party attributions.

---

## Still Have Questions?

- **Support guide**: [SUPPORT.md](../SUPPORT.md)
- **Issues**: [github.com/Xmar1881/Gash/issues](https://github.com/Xmar1881/Gash/issues)
- **Security**: [Private advisory](https://github.com/Xmar1881/Gash/security/advisories/new)
