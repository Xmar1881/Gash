<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/auth.md
What: Authenticated scan contexts (--auth-header/--cookie/--basic-auth).
Why: requires_auth plugins need credentials; credentials must not leak.
-->

# Authenticated Scans

Plugins with `requires_auth: true` are skipped unless the scan carries an
authentication context. Provide one (or more) of:

```sh
gash scan --target https://app.example.com --scope app.example.com \
  --auth-header "Authorization: Bearer <token>" \
  --cookie "session=<id>; theme=dark" \
  --basic-auth "user:password"
```

## Semantics

- `--auth-header "Name: value"` (repeatable): sent as-is on every request.
- `--cookie "a=b[; c=d]"` (repeatable): merged into one `Cookie` header.
- `--basic-auth "user:password"`: sent as `Authorization: Basic ...`.
- Precedence: an explicitly set request header is never overwritten by the
  context (explicit wins).
- Any of the three sets the engine `HasAuth` gate, so `requires_auth`
  plugins become runnable. Scope, budget, and safe/active policy still apply
  unchanged — auth does not widen scope or authorize destructive payloads.

## Validation (fail-closed)

- `Name: value` shape required; empty names/values rejected.
- CR/LF anywhere in names or values is rejected (header-injection guard).
- `--basic-auth` requires the `user:password` shape (password may be empty).

## Redaction

Credential **values never appear** in findings, reports, or logs. The CLI
prints only a redacted summary to stderr:

```text
auth: headers=[Authorization] cookies=[session,theme] basic=yes(user=admin)
```

Store tokens in CI secret storage or environment-fed wrappers; never commit
them, never paste them into issue reports.
