<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/db-unauthenticated-access.md
What: Unit-test report for the proto DB unauthenticated-access probe (GASH-055).
Why: Proves unauth grading fires only on proven anonymous responses (no FP).
-->

# Metrics: db-unauthenticated-access (proto, GASH-055)

## Overview

Engine infra recon (`engine.runInfraRecon`, `--db-unauth`, `--active` +
`db` detector). `internal/proto/db.go` sends exactly one harmless request
per supported service with the fixed dummy identity `gash_probe`:
Redis `PING` (only `+PONG` proves; one optional `INFO server` read for the
version), Memcached `version`, MongoDB legacy `OP_QUERY` `hello` on
`admin.$cmd` (`ok:1` proves), PostgreSQL `StartupMessage` (trust /
`AuthenticationOk` proves; no password is ever sent), MySQL greeting
metadata only (no login attempted, no unauth claim). Unsupported ports
return a note with zero dials. Rule GASH-055 (CWE-306): proven `Unauth`
→ one `high`/`firm` finding; `AuthRequired` and indeterminate results
never fire; `confirmed` never fires (no data was read or written).

## Evidence Standard

Finding carries `host`, `port`, `service`, `version`, `auth_method`,
`banner`, `note`, `signal` (`db-unauth-<service>`), and
`max_wire_version` when the MongoDB hello reply provided one. Findings
state what was observed (no credential was demanded for that single
request), not that data is readable; notes state the dummy identity and
the single-request boundary.

## Unit Cases (no fixtures; no external DB)

- Redis loopback (6379): `+PONG` + `INFO server` → 1 `db-unauth-redis`
  finding, version `7.2.4`, high/`firm`; `-NOAUTH` → silent with
  `AuthRequired`/`requirepass`.
- Memcached loopback (11211): `VERSION 1.6.21` → 1 finding, version
  captured.
- MongoDB loopback (27017): OP_REPLY `{ok:1, maxWireVersion:13, version}`
  → 1 finding with `max_wire_version=13`; `{ok:0, code:13, errmsg:...
  authentication}` → silent with `SCRAM (code 13)`; the client packet is
  verified to be the harmless `admin.$cmd hello` query.
- PostgreSQL loopback (5432): `R0` (trust) + `server_version` → 1 finding,
  `auth_method=trust`; `R5` (MD5) → silent, `md5-password`; the startup
  packet is verified to carry `gash_probe` and protocol 3.0.
- MySQL loopback (3306): greeting with `CLIENT_PLUGIN_AUTH` → metadata
  only (`8.0.35`, `mysql_native_password`), 0 findings by construction.
- Unsupported port (27099): note `desteklenmiyor`, zero dials, 0 findings;
  invalid port 0 and empty host → error.
- Scope/IP/nil: nil `Allow` → error; deny → error; zero accepted sockets
  in both cases (fail-closed).
- Engine gates: `--active` off → `skipped (requires --active)`, zero
  dials; live run → `db_unauth_checks=1` and one GASH-055 finding with
  `signal=db-unauth-redis`.
- Command: `go test ./internal/proto/ -run 'DBUnauth' -v` and
  `go test ./internal/engine/ -run 'DBUnauth' -v`.

## Corpus Result

Proto DB checks read no HTTP bodies; corpus `firm` is unaffected by
construction.

## Lab Result

Hermetic lab is the loopback mock set above (real wire formats: RESP,
memcached text, OP_QUERY/OP_REPLY BSON, PostgreSQL v3 startup,
MySQL handshake v10; no external DB). No real-target recall is claimed.

## Precision

Unit true positives 5 (Redis, Memcached, Mongo hello, PostgreSQL trust,
engine live); false positives 0 (NOAUTH, Mongo code 13, PostgreSQL MD5,
MySQL metadata, unsupported port, empty/absent results all stay silent).
Precision 1.00 (unit-scoped, not real-target recall).

## Recall

All four supported unauth paths fire in unit scope; false negatives 0 in
scope. MySQL unauth is deliberately out of scope (no login attempted) and
is not counted.

## Gate Verdict

PASS (unit-scoped). Engine infra recon has no plugin ID or fixtures, so
`TestMetricGate` does not apply; the gate is `go test ./...` plus
`go vet ./...`, both green.

## Limitations

- Service identity is port-keyed; a non-DB service on a known DB port
  yields a failed/indeterminate probe, never a finding.
- MongoDB `hello` may answer `ok:1` while auth is enabled (the command is
  unauthenticated by design); collection access is not proven and the
  finding says so.
- Redis `PING` is answered in default protected-mode for loopback clients;
  `+PONG` proves command reachability for the probe path, not full data
  access (`INFO` is the only extra read).
- PostgreSQL trust detection needs a reachable startup path; `pg_hba`
  rejections produce a note, never a finding. TLS-wrapped DB ports are not
  probed in this phase.

## Dataset

No fixtures. Hermetic unit tests only (loopback mocks; tests skip if the
service port is occupied locally). Re-run the commands above; any
behaviour change must update this report, never imply real-target recall.
