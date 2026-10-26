/* ---
id: cors-null-origin-trust
name: CORS Trusts the null Origin
description: "Detects CORS policies that answer the literal null origin by sending a canary null Origin header and grading the echoed Access-Control-Allow-Origin against the credential flag; null is reachable from sandboxed iframes and data URLs, so a null allowlist is a real bypass."
author: GASH contributors
severity: high
tags: [cors, misconfig, client, null-origin]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 30
phase: probe
order: 78
api_version: "1.0"
tests: tests/fixtures/cors-null-origin-trust/
oracle_params:
  request_origin: "null"
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/cors/cors-null-origin-trust.js
// What: Tier 2 null-origin CORS plugin.
// Why: The reflected-origin plugin proves that an arbitrary origin is echoed;
//   a policy can reject arbitrary origins yet still special-case "null", which
//   is the origin a sandboxed iframe or a data: URL sends and which cannot be
//   allowlisted safely. Proving it needs the request to actually carry the
//   literal null Origin (a point-level header), and the origin literal is
//   declared once in the frontmatter oracle_params block so the fixture runner
//   and a live scan grade the same value.

const NULL_ORIGIN = "null";

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const maxSends = 30;
  let sends = 0;
  const seen = {};

  for (const point of points) {
    const base = String(point.url || "").split("#")[0];
    if (!base || seen[base]) {
      continue; // one origin probe per URL
    }
    seen[base] = true;
    if (sends >= maxSends) {
      break;
    }
    sends++;
    const resp = probe.send({
      url: base,
      method: "GET",
      paramName: "",
      paramLocation: "query",
      value: "",
      headers: { Origin: NULL_ORIGIN },
    });
    // The oracle reads the request Origin from oracle_params; passing it here
    // keeps script and frontmatter provably in sync (asserted in the tests).
    const ev = host.oracles.cors(resp, { requestOrigin: NULL_ORIGIN });
    if (ev) {
      candidates.push(host.candidate(point, "cors-misconfig", ev));
    }
  }
  return candidates;
}
