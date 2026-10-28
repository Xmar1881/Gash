<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/report-formats.md
What: Extensible reporter registry (package internal/reporter).
Why: New formats are a Register call, not a CLI switch change.
-->

# Report Formats

`gash scan --format` accepts any name registered in `internal/reporter`:

`static-execution-evidence` is visible in JSON, text, and HTML, maps to SARIF
`note`, and remains a skipped JUnit testcase. It does not satisfy the
`--fail-on firm` or `--fail-on confirmed` gates. JSON findings carry
`evidence_type` (`static-execution-evidence` vs `browser-confirmed`);
SARIF results carry the same value in `properties.evidenceType`.

| Format | Content | Primary use |
|---|---|---|
| `text` | Human-readable terminal summary | Operators |
| `json` | Findings, `scan_id`, `skipped`, `suppressed`, `stats`, `noisy_notes` | Automation, diffing |
| `sarif` | SARIF v2.1.0 (`confirmed`→error, `firm`→warning, `tentative`→note) + `properties.evidenceType` | Code scanning, `--fail-on` gates |
| `html` | Single-file inline-CSS stakeholder report | Sharing |
| `junit` | JUnit XML (`firm`/`confirmed`→failure, `tentative`/skipped→skipped) | Jenkins/GitLab/ADO (see `docs/ci-integration.md`) |

Repeat `--format` (or comma-separate) for stdout fan-out; `--output`
requires exactly one format so files stay parseable.

## JSON audit schema

`findings` is the visible finding array. Each entry carries the finding
identity (`id`, `rule_id`, `cwe`, `title`, `severity`, `confidence`,
`fingerprint`), the audit trail (`plugin_id`, `oracle_name`, `method`,
`injection_point`, `verification_method`, `note`, `detector_version`,
`evidence`, `evidence_type`), and remediation metadata when present
(`references`, `remediation`, `masked`).

`stats` always describes the array written by the reporter:

| Key | Meaning |
|---|---|
| `findings` / `findings_visible` | Findings in the JSON array |
| `findings_total` | Deduplicated findings before the tentative/suppress filter |
| `findings_tentative_hidden` | Hidden because `--show-tentative` was not set |
| `findings_suppressed` | Hidden by a local suppression |
| `scheduled`, `skipped`, `partial_plugins`, `errors`, `retry_budget_exhausted` | Run accounting |
| `request_budget_target`, `request_budget_total`, `rate_limit_per_second` | Effective engine limits for this run |
| `max_pages`, `crawl_depth` | Crawl bounds applied to the run |
| `passive_cache_hits`, `passive_cache_fetches` | Static GET/HEAD responses served from the scan cache vs fetched over the network |
| `plugin_selection`, `plugin_exclusions` | Positive `--only-plugin` set size and `--ignore-plugin` count (0 when unused) |

`skipped` entries are objects with lowercase `plugin_id`, `reason`, and
`partial` keys. `findings` and `skipped` always serialize as arrays (an empty
scan writes `[]`, never `null`). `noisy_notes` is present when the engine
recorded context such as WAF challenges or proxy direct fallbacks. Text reports
end with a compact `summary:` line (requests, cache hits, scheduled, partial,
errors, duration) so terminal and menu readers see the same accounting without
opening JSON.

## Adding a format (developers)

Implement the writer contract and register it — no CLI change needed:

```go
func WriteCSV(w io.Writer, rep *engine.Report, opts reporter.Options) error { ... }

func init() {
    if err := reporter.Register("csv", WriteCSV); err != nil { panic(err) }
}
```

Rules: names are lowercased; duplicate registration fails (fail-closed);
unknown `--format` values fail fast listing the registered names.
`tentative` stays hidden unless `Options.ShowTentative` is set — apply the
shared `filter()` helper so every format honors it identically.
