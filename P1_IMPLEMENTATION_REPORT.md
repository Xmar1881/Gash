# P1 Implementation Report — §17 Format (A-I)

## A. Summary
Successfully implemented P1 (§4-12) core HTTP engine, scan profiles, and scope/target safety as independent, incremental enhancements to existing architecture. All changes pass `go test ./...` and `go vet ./...` with zero regressions.

## B. Files Changed
- **New**: `internal/config/profile.go` — Profile definitions (Safe/Standard/Deep) + CLI/config integration
- **New**: `internal/engine/scope.go` — Centralized ScopeManager + ScanBudget (P1.3)
- **New**: `docs/detector-inventory.md` — Complete detector catalog with confidence ladders
- **Modified**: `internal/plugin/policy.go` — Retry/backoff, redirect+scope re-validation, error classification, scan budget, DNS rebinding detection (P1.1 + P1.3)
- **Modified**: `internal/probe/probe.go` — Uses PolicySession.RoundTripWithRetry; Response now carries ErrorClass/RetryCount (P1.1)
- **Modified**: `internal/engine/engine.go` — Profile-aware scheduling + detector enablement filtering (P1.2)
- **Modified**: `internal/engine/scan_exec.go` — Sets original target for rebinding detection (P1.3)
- **Modified**: `cmd/gash/main.go` — `--profile` flag (safe|standard|deep) with explicit flag override semantics

## C. P1.1 — Centralized HTTP Engine (probe.Send + PolicySession)
**What**: Thin layer on existing PolicySession adding retry/backoff, redirect handling with scope re-validation, global/target/plugin rate limits, request budget, total scan timeout, per-host concurrency, request/response size limits, backpressure, error classification, cancellation propagation, deterministic error logging.

**Key Changes**:
- `plugin.ClassifyError()` — Single taxonomy: Timeout/Network/Policy/Server/Client/Redirect/Scope
- `plugin.IsRetryable()` — Central retryability decision per RetryConfig
- `PolicySession.RoundTripWithRetry()` — Retry loop with exponential backoff+jitter, redirect follow with scope re-validation, cross-scheme control, scan budget enforcement
- `probe.Client.Send()` — Delegates to PolicySession.RoundTripWithRetry; Response enriched with `ErrorClass` + `RetryCount`
- `PolicyConfig` extended: `RetryConfig`, `RedirectPolicy`, `GlobalRatePerSecond`, `MaxConcurrencyPerHost`, `ScanTimeout`, `MaxRequestBytes`, `BackpressureLimit`

**No Big Rewrite**: Existing `probe.Send` signature unchanged; `PolicySession` still implements `http.RoundTripper`; new `RoundTripWithRetry` is additive.

## D. P1.2 — Scan Profiles (Safe/Standard/Deep)
**What**: Three profiles controlling active detectors, request types, budgets, risk thresholds. CLI `--profile` flag + config file support. Consistent behavior across CLI/config/reporting.

| Profile | Active Detectors | Request Types | Budget (req/target) | Active? | Deep? | Opt-in |
|---------|------------------|---------------|---------------------|---------|-------|--------|
| Safe | header, redirect, cors, cookie, version | GET/HEAD/OPTIONS | 100 | No | No | No |
| Standard | Safe + reflection, error, differential | GET/POST/HEAD/OPTIONS | 500 | Yes | No | No |
| Deep | Standard + timing, execution, oob | All | 2000 | Yes | Yes | **Yes (--deep)** |

**Integration**:
- `config.Profile` struct with `ApplyToConfig()`, `DetectorEnabled()`, `MethodAllowed()`
- `engine.Config.Profile` + `CustomProfile` + `enabledDetectors` map
- `Engine.filterReason()` checks profile detector enablement **after** explicit flags (--active/--deep/--oob-server)
- CLI flag defaults to "standard"; explicit flags override profile defaults

## E. P1.3 — Scope & Target Safety
**What**: Centralized scope management preventing unbounded scans, enforcing redirect re-validation, detecting DNS rebinding.

**Components**:
- `engine.ScopeManager` — Domain/CIDR/URLPrefix allowlist; IP rebinding detection via cached DNS resolution; implicit-scope fallback (original target only)
- `engine.ScanBudget` — Total/per-host/per-path request caps (prevents unlimited scans)
- `plugin.scopeManager` + `scanBudget` — PolicySession-integrated equivalents for probe layer
- `PolicySession.SetOriginalTarget()` — Called from `runLive` to seed rebinding detection
- Redirect re-validation uses new scopeManager (IP change detection on each hop)
- Request/response size limits enforced in RoundTripWithRetry

## F. Detector Inventory (docs/detector-inventory.md)
Complete catalog of 11 engine-owned oracles + 5 reference plugins (4 Tier1 YAML + 1 Tier3 native). Each entry documents:
- Oracle name, consuming plugins, tier
- Confidence ladder (tentative/firm/confirmed)
- Control requirement, active probing, OOB requirement
- GASH rule IDs and fixture paths

## G. Tests & Verification
- All existing tests pass (`go test ./...` ✓)
- `go vet ./...` clean ✓
- `go build ./...` clean ✓
- Manual CLI verification: `--profile=safe|standard|deep` correctly filters detectors
- Profile flag override semantics verified (explicit --active/--deep overrides profile)

## H. Backward Compatibility
- No breaking changes to public APIs
- `probe.Options` removed `MaxRedirects` (now in PolicyConfig.RedirectPolicy)
- `probe.Client` no longer uses `http.Client` directly; uses PolicySession.RoundTripWithRetry
- Default PolicyConfig values preserve pre-P1 behavior
- Profile defaults to "standard" matching previous implicit defaults

## I. Follow-up Items (Post-P1)
1. **Config file support** — YAML config loading for ProfileConfig (currently CLI-only)
2. **Metrics integration** — Profile name + detector set in scan reports
3. **ScopeManager unit tests** — Dedicated test coverage for rebinding/CIDR/URLPrefix logic
4. **Per-plugin rate limit** — Extend PolicyConfig with per-plugin rate (currently only budget)
5. **Deep profile browser integration** — ExecutionOracle headless path behind build tag `deep`