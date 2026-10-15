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
| `json` | Findings + scan_meta + skipped + stats | Automation, diffing |
| `sarif` | SARIF v2.1.0 (`confirmed`→error, `firm`→warning, `tentative`→note) + `properties.evidenceType` | Code scanning, `--fail-on` gates |
| `html` | Single-file inline-CSS stakeholder report | Sharing |
| `junit` | JUnit XML (`firm`/`confirmed`→failure, `tentative`/skipped→skipped) | Jenkins/GitLab/ADO (see `docs/ci-integration.md`) |

Repeat `--format` (or comma-separate) for stdout fan-out; `--output`
requires exactly one format so files stay parseable.

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
