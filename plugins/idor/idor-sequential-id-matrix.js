/* ---
id: idor-sequential-id-matrix
name: IDOR Access Matrix (sequential identifiers, differential)
description: Detects horizontal authorization gaps by reading the caller's own object, a neighbouring identifier and a non-existent identifier over three repeats and confirming only when the neighbour diverges from both the caller's object and the missing-object baseline.
author: GASH contributors
severity: high
tags: [idor, bola, authorization, differential, api]
safe: false
deep: false
active: true
requires_auth: true
max_requests: 60
phase: probe
order: 67
api_version: "1.0"
tests: tests/fixtures/idor-sequential-id-matrix/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/idor/idor-sequential-id-matrix.js
// What: Tier 2 IDOR/BOLA matrix plugin (own, neighbour, missing identifiers).
// Why: A single-request IDOR check can only compare one object against a
//   static expectation. The proof needs three correlated reads of the SAME
//   point with different identifiers: the caller's own object is the control,
//   a neighbouring identifier is the true branch, and an identifier that cannot
//   exist is the false branch. Only when the neighbour is stable AND differs
//   from both the caller's object and the missing-object baseline does the
//   response prove that another tenant's object was served. An authenticated
//   session is required for the divergence to mean an authorization gap.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const maxSends = 60;
  let sends = 0;
  const seen = {};

  for (const point of points) {
    const loc = String(point.paramLocation || "query").toLowerCase();
    if (loc !== "query" && loc !== "body") {
      continue;
    }
    if (!point.paramName) {
      continue;
    }
    const own = identifier(point.value);
    if (own === null) {
      continue; // only numeric identifiers form a contiguous space
    }
    const key = String(point.url || "").split("#")[0] + "|" + point.paramName;
    if (seen[key]) {
      continue;
    }
    seen[key] = true;
    if (sends + 10 > maxSends) {
      break;
    }

    // Control: the caller's own object.
    sends++;
    const ownResp = probe.send(point.withValue(String(own)));

    // True branch: a neighbouring identifier (another tenant's object).
    const others = [];
    for (let i = 0; i < 3; i++) {
      sends++;
      others.push(probe.send(point.withValue(String(own + 1))));
    }

    // False branch: an identifier that cannot exist, in the same space.
    const missing = [];
    for (let i = 0; i < 3; i++) {
      sends++;
      missing.push(probe.send(point.withValue(String(own + 100000))));
    }

    // Pre-gate: if the neighbour came back identical to the caller's own
    // object the endpoint ignored the identifier, which proves nothing.
    if (!others[0] || !ownResp || sameBody(others[0], ownResp)) {
      continue;
    }
    if (missing[0] && sameBody(others[0], missing[0])) {
      continue; // neighbour and missing look alike: no distinct object
    }

    const ev = host.oracles.differential(others, missing, ownResp);
    if (ev) {
      candidates.push(host.candidate(point, "differential", ev));
    }
  }
  return candidates;
}

// identifier returns the numeric value of a discovered point, or null when the
// point does not carry a numeric identifier.
function identifier(value) {
  const text = String(value === undefined || value === null ? "" : value).trim();
  if (text === "" || !/^[0-9]{1,12}$/.test(text)) {
    return null;
  }
  const n = parseInt(text, 10);
  if (isNaN(n)) {
    return null;
  }
  return n;
}

// sameBody reports whether two responses carry the same body.
function sameBody(a, b) {
  return Boolean(a) && Boolean(b) && String(a.body) === String(b.body);
}
