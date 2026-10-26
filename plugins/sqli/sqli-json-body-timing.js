/* ---
id: sqli-json-body-timing
name: SQL Injection in JSON Body (blind time-based)
description: Detects blind time-based SQL injection in JSON API bodies by injecting delay payloads into each discovered field with an explicit application/json content type and comparing measured latencies against a neutral-value baseline.
author: GASH contributors
severity: high
tags: [sqli, injection, blind, timing, json, api]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 80
api_version: "1.0"
tests: tests/fixtures/sqli-json-body-timing/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/sqli/sqli-json-body-timing.js
// What: Tier 2 time-based blind SQLi plugin for JSON request bodies.
// Why: The error and boolean JSON plugins need an in-band signal. When the
//   endpoint returns a stable response regardless, only the latency of the
//   injected request itself differs, which needs the field rebuilt as JSON and
//   a measured baseline. Ceiling is firm: timing carries no confirmation.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const payloads = ["1' AND SLEEP(5)-- ", "1'; WAITFOR DELAY '0:0:5'-- "];
  const jsonContentType = "application/json";
  const repeats = 3;
  const minDelayMs = 5000;
  const maxSends = 60;
  const sendsPerPoint = repeats + payloads.length * repeats;
  let sends = 0;

  for (const point of points) {
    if (String(point.paramLocation || "").toLowerCase() !== "body") {
      continue;
    }
    if (!point.paramName) {
      continue;
    }
    if (sends + sendsPerPoint > maxSends) {
      break;
    }
    const name = point.paramName;
    const raw = (value) => ({
      url: point.url,
      method: point.method,
      paramName: "",
      paramLocation: "body",
      value: '{"' + name + '":"' + value + '"}',
      headers: { "Content-Type": jsonContentType },
    });

    // Baseline latencies first: a slow endpoint must not look like an
    // injected delay.
    const controlResps = [];
    for (let i = 0; i < repeats; i++) {
      sends++;
      controlResps.push(probe.send(raw("1")));
    }
    for (const payload of payloads) {
      const delayResps = [];
      for (let i = 0; i < repeats; i++) {
        sends++;
        delayResps.push(probe.send(raw(payload)));
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
