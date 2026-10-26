/* ---
id: insecure-cors-reflected-origin
name: CORS Reflected Origin with Credentials
description: Detects CORS misconfiguration where the response reflects an arbitrary Origin, proving cross-origin readable responses by sending a canary Origin header and grading the echoed Access-Control-Allow-Origin against the credential flag.
author: GASH contributors
severity: high
tags: [cors, misconfig, client, json]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 30
phase: probe
order: 77
api_version: "1.0"
tests: tests/fixtures/insecure-cors-reflected-origin/
oracle_params:
  request_origin: https://gash-cors-canary.example
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/cors/insecure-cors-reflected-origin.js
// What: Tier 2 reflected-origin CORS plugin.
// Why: The wildcard case is a single passive read a Tier 1 plugin can do. The
//   dangerous case is an allowlist that echoes whatever Origin it is given:
//   proving it needs the request to actually carry our Origin, which is a
//   point-level header. The origin literal is declared once in the frontmatter
//   oracle_params block and asserted equal in the plugin test, so the fixture
//   runner and a live scan send and grade the same value.

const REFLECT_ORIGIN = "https://gash-cors-canary.example";

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
      headers: { Origin: REFLECT_ORIGIN },
    });
    // The oracle reads the request Origin from oracle_params; passing it here
    // keeps script and frontmatter provably in sync (asserted in the tests).
    const ev = host.oracles.cors(resp, { requestOrigin: REFLECT_ORIGIN });
    if (ev) {
      candidates.push(host.candidate(point, "cors-misconfig", ev));
    }
  }
  return candidates;
}
