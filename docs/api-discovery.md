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
and prints a deterministic endpoint/parameter test plan. **It does not scan**:
the only network call is the single explicit spec fetch.

```sh
# Local file:
gash openapi --spec ./openapi.json

# Remote document (fetched once, never probed):
gash openapi --spec https://api.example.com/openapi.json --format json

# Override the base server for the printed targets:
gash openapi --spec ./openapi.yaml --server https://staging.example.com
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
