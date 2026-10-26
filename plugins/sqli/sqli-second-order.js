/* ---
id: sqli-second-order
name: SQL Injection (second-order, in-band)
description: Detects second-order SQL injection by writing an error-prone payload at an injection point and re-reading the same point with a neutral value, comparing database error signatures against a pre-write control.
author: GASH contributors
severity: high
tags: [sqli, injection, second-order, blind]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 120
phase: probe
order: 59
api_version: "1.0"
tests: tests/fixtures/sqli-second-order/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/sqli/sqli-second-order.js
// What: Tier 2 second-order SQLi plugin (write, then neutral re-read).
// Why: Tier 1 declares a single request per payload, so it can only prove
//   first-order injection. Second-order injection stores the payload and
//   surfaces later on a neutral request; proving it needs at least two
//   correlated exchanges, which only a Tier 2 script can sequence.
//   No new sandbox surface: only probe.send plus the ctx surface plus
//   host.oracles.error plus host.candidate.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  // Error-prone closures; the write exchange stores them, the read-back
  // exchange carries a neutral value so any signature here is state-borne.
  const payloads = ["'", "1')", "1' AND '1'='2"];
  const neutral = "1";
  const maxSends = 120;
  // 1 baseline read + (1 write + 1 read) per payload.
  const sendsPerPoint = 1 + payloads.length * 2;
  let sends = 0;

  for (const point of points) {
    const loc = String(point.paramLocation || "query").toLowerCase();
    if (loc !== "query" && loc !== "body") {
      continue;
    }
    if (!point.paramName) {
      continue;
    }
    if (sends + sendsPerPoint > maxSends) {
      break;
    }
    // Step 1: baseline read BEFORE any write. A signature here is pre-existing
    // noise, never second-order proof, so it becomes the control body.
    sends++;
    const baseline = probe.send(point.withValue(neutral));
    if (!baseline) {
      continue;
    }
    let found = false;
    for (const payload of payloads) {
      if (found) {
        break;
      }
      // Step 2: write the payload (the first-order response is deliberately
      // not used as evidence; first-order reflection is a different class).
      sends++;
      probe.send(point.withValue(payload));
      // Step 3: neutral re-read. A database error the baseline never showed
      // can only come from the state the write left behind.
      sends++;
      const readBack = probe.send(point.withValue(neutral));
      if (!readBack) {
        continue;
      }
      const ev = host.oracles.error(readBack, baseline);
      if (ev) {
        candidates.push(host.candidate(point, "sqli-error", ev));
        found = true;
      }
    }
  }
  return candidates;
}
