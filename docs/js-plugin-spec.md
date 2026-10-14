<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/js-plugin-spec.md
What: Tier 2 sandboxed JavaScript plugin specification.
Why: Documents frontmatter, sandbox limits, and the host binding contract.
-->

# JS Plugin Spec

## Purpose

Tier 2 covers logic that declarative YAML cannot express: branching,
multi-step correlation, and per-point decisions. Scripts run inside a goja
VM sandbox with host-injected bindings only. Files use `.js` and are
discovered automatically.

## File Layout

```js
/* ---
id: xss-reflected-basic
name: Reflected XSS (basic contexts)
description: Detects reflected XSS via canary reflection in executable HTML contexts.
author: GASH contributors
severity: high
tags: [xss, client]
safe: true
deep: false
active: false
requires_auth: false
phase: probe
order: 40
api_version: "1.0"
tests: tests/fixtures/xss-reflected-basic/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  for (const point of points) {
    const canary = probe.canary();
    const resp = probe.send(point.withValue(canary));
    const ev = host.oracles.reflection(resp, canary, ["html", "attr", "script"]);
    if (ev) {
      candidates.push(host.candidate(point, "reflected-xss", ev));
    }
  }
  return candidates;
}
```

The frontmatter is fixed-format `/* --- ... --- */` YAML. Variants are
rejected; the VM never starts during discovery, so warm discovery stays
under budget. The file must define a top-level `run(probe, ctx)` function
returning an array.

## Frontmatter Format

- Starts with exactly `/* ---` on the first non-whitespace characters.
- Ends with exactly `--- */`. Inner content is `PluginSpec` YAML.
- Same field rules as Tier 1 (`id` slug, `severity` enum, `phase` enum,
  `api_version: "1.0"`). `tier` is never written by hand.
- Missing or unclosed frontmatter fails validation before any execution.

## Sandbox Rules

- Available globals: `probe`, `ctx`, `host` only. `require`, file I/O, raw
  sockets, `fetch`, and Node APIs do not exist.
- `eval` and the `Function` constructor are disabled by the host.
- Regular expressions must not carry security decisions; matching runs
  through Go `regexp` (RE2, no backtracking) inside oracles.
- CPU is bounded (`SetMaxCallStackSize` plus execution timeout);
  `--plugin-timeout` interrupts via `vm.Interrupt`. Infinite loops become
  `timeout` results, never hung scans.
- World-writable files or directories are skipped with a warning.
- Every network call goes through `probe.send`; direct egress is impossible
  by construction.

## Probe API

- `probe.canary()`: fresh unique marker per call. Never invent canaries.
- `probe.send(point)`: sends one request through `PolicySession` (budget,
  scope, rate limit, safe-method checks) and returns
  `{status, headers, body, url, rttMs}` (`rttMs` is the Go-measured
  round-trip in milliseconds for `host.oracles.timing`).
- Points come from `ctx.injectionPoints()` as
  `{url, method, paramName, paramLocation, value}` with
  `point.withValue(next)` returning an updated copy.

## Oracle API

- `host.oracles.reflection(resp, canary, contexts)`: executable-context
  reflection plus clean-control comparison. Returns evidence or `null`.
- `host.oracles.error(resp, controlResp)`: DB signature plus control
  absence. Returns evidence or `null`.
- `host.oracles.differential(trueResps, falseResps, controlResp)`:
  masked true/false/control comparison over repeat sets.
- `host.oracles.header(resp)`: passive header verdict, never tentative.
- `host.oracles.redirect(resp, payloadHost)`: external-host redirect with
  control semantics.
- `host.oracles.oob(correlationId, namespace)`: OOB verdict; skipped when
  the server is unconfigured (not an error).
- `host.oracles.timing(delayResps, controlResps[, opts])`: statistical timing
  verdict over Go-measured `rttMs` series. `opts` accepts `min_delay_ms`
  (default 5000), `repeats` (minimum 3), `strategy` (`mann-whitney-u` or
  `threshold`), and `baseline_stddev`. Ceiling is `firm`; no new network
  primitive is exposed (sandbox risk minimal: only timing of already-allowed
  `probe.send` calls is visible).
- `host.oracles.execution(resp[, opts])`: static DOM sink/source verdict
  without a browser. `opts` accepts `sink`/`source` overrides; empty auto-
  detects from the static vocabulary. Ceiling is `firm`; `confirmed` needs
  the headless build (`Triggered` plus `ControlClean`), which is BLOCKED
  without browser dependencies (see `docs/metrics/dom-sink-basic.md`).
- `host.candidate(point, oracleRef, ev)`: builds the opaque candidate for
  accepted evidence; returns `null` for rejected evidence. Accepted refs
  include `reflected-xss`, `sqli-error`, `sqli-differential`, `ssrf-blind`,
  `header`, `redirect`, `timing`.
- `host.oob.generate(channel)`: fresh `{url, correlationId, namespace}` or
  `null` when OOB is disabled. A `null` means skip honestly.

Only oracle-returned evidence counts. Fabricated objects never become
findings because the runner tracks evidence identity internally.

## Safe Active Deep OOB Rules

Same engine enforcement as Tier 1: `safe` limits methods, `deep` and
`active` gate execution, `oob: required` without `--oob-server` never runs.
Blind plugins (`ssrf-blind-oob`) must check `host.oob.generate` for `null`
and `continue` instead of emitting tentative noise.

## Fixtures

Tier 2 fixtures use the same JSON shape as Tier 1. `gash plugins test`
infers the oracle from the first `host.oracles.<name>` reference without
executing the script, then runs the fixture set through the real Go oracle:

```sh
go run ./cmd/gash plugins new my-xss --tier js
go run ./cmd/gash plugins test my-xss.js
```

The starter ships reflection fixtures (script-block positive, text-only and
absent negatives) at precision 1.00.

## Validation

```sh
go run ./cmd/gash plugins validate plugins/xss/xss-reflected-basic.js
```

Checks frontmatter shape, `PluginSpec` rules, OOB discipline, and fixture
presence. `run()` existence and return-type checks happen at execution time;
invalid returns become plugin errors without stopping the scan (B7).

## Examples

- Reflected XSS: `plugins/xss/xss-reflected-basic.js`.
- Error SQLi: `plugins/sqli/sqli-error-based.js`.
- Differential SQLi: `plugins/sqli/sqli-boolean-differential.js`.
- Blind SSRF (OOB required): `plugins/ssrf/ssrf-blind-oob.js`.
- Starter template: `templates/template.js` plus
  `templates/tests/fixtures/template-js/`.
