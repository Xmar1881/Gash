<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/api-discovery.md
What: OpenAPI/Swagger test-plan generation (`gash openapi`).
Why: Enumerate the API surface before scanning; review beats blind fuzzing.
-->

# API Discovery (OpenAPI/Swagger)

`gash openapi` parses an OpenAPI 3.x or Swagger 2.0 document (JSON or YAML)
and prints a deterministic endpoint/parameter test plan. **`gash openapi`
itself does not scan**: the only network call is the single explicit spec
fetch. To feed that surface into a scan, use `gash scan --openapi-spec` —
the plan endpoints/parameters are resolved against the scan target and added
to the scan surface automatically.

```sh
# Local file:
gash openapi --spec ./openapi.json

# Remote document (fetched once, never probed):
gash openapi --spec https://api.example.com/openapi.json --format json

# Override the base server for the printed targets:
gash openapi --spec ./openapi.yaml --server https://staging.example.com

# Scan with the spec as extra surface (file or in-scope/loopback URL):
gash scan --target http://127.0.0.1:8080 --openapi-spec ./openapi.json
gash scan --target http://127.0.0.1:8080 --scope 127.0.0.1/32 \
  --openapi-spec http://127.0.0.1:8080/openapi.json
```

## Output

- `text` (default): servers, `METHOD /path` targets, per-endpoint
  `params=[in:name, ...]`, and the endpoint count.
- `json`: the full plan (`title`, `version`, `servers`, `endpoints[]`
  with `method`, `path`, `params[]`, `operation_id`).

Path-level `parameters` are merged into each operation; duplicate
`(in, name)` pairs are de-duplicated. OpenAPI 3.x `requestBody` surfaces as
a `(body)` parameter signal. `$ref` parameters without an inline `name` are
skipped (the plan shrinks honestly rather than guessing).

## Limits (deliberate)

- Spec size cap: 10 MB local, 2 MB remote fetch.
- Remote fetch: single `GET`, no redirect following (fail-closed),
  `http(s)` only, no userinfo in URL.
- The plan is a candidate list, not a target list: scope decisions stay in
  `gash scan --scope`. Servers from the spec are printed, never requested.

## `scan --openapi-spec` behavior

- Accepts a file path or an `http(s)` URL. Remote URLs are fetched only if
  loopback (`localhost`/loopback IP) or inside `--scope`; out-of-scope URLs
  fail **before** any fetch (no out-of-scope fetch, destructive action none).
- `ParseSpec` endpoints/parameters become extra `surfacePoints`: each path is
  resolved as `target-scheme://target-host[:port] + path` (`{param}` → `1`),
  one point per parameter (plus a bare point for param-less operations).
- Paths resolving to a different host than the scan target, or failing the
  scope check, are skipped at insert time (`PolicySession` stays the second
  lock at probe time). No new scan level is added: the points flow through
  the existing fuzz/matrix/plugin pipeline.
