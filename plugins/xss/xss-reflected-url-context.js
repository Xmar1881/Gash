/* ---
id: xss-reflected-url-context
name: "Reflected XSS in URL Sinks (javascript: schemes)"
description: "Detects reflected XSS where the injected value lands in a URL sink (href/src/action) by sending a javascript: scheme payload and grading it with the URL-executable reflection context plus a clean control."
author: GASH contributors
severity: high
tags: [xss, client, reflection, url-sink]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 47
api_version: "1.0"
tests: tests/fixtures/xss-reflected-url-context/
oracle_params:
  contexts: [url-executable]
  require_executable_context: true
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/xss/xss-reflected-url-context.js
// What: Tier 2 reflected-XSS plugin for URL sinks.
// Why: The basic reflected plugin sends markup payloads (svg/img/script) and
//   grades html/attr/script contexts. A value that lands inside href/src never
//   needs markup: the sink itself is the dangerous part, and only a
//   javascript: (or data:) scheme executes there. Tier 1 sends one fixed
//   payload per file, so it cannot pick the scheme payload for exactly the
//   points whose response is a URL sink. Evidence stays with the reflection
//   oracle (URL-executable context + clean control); no new sandbox surface.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const maxSends = 40;
  let sends = 0;

  for (const point of points) {
    const loc = String(point.paramLocation || "query").toLowerCase();
    if (loc !== "query" && loc !== "body") {
      continue;
    }
    if (!point.paramName) {
      continue;
    }
    if (sends + 2 > maxSends) {
      break;
    }
    const canary = probe.canary();
    // Harmless scheme probe: the dialog carries the canary, nothing else runs.
    const payload = "javascript:alert(" + canary + ")";
    sends++;
    const resp = probe.send(point.withValue(payload));
    if (!resp || !resp.body || String(resp.body).indexOf(canary) === -1) {
      continue; // the value never reaches the response: nothing to grade
    }
    const ev = host.oracles.reflection(resp, canary, ["url-executable"]);
    if (ev) {
      candidates.push(host.candidate(point.withValue(payload), "reflected-xss", ev));
      continue;
    }
    // Naive scheme blacklists match the lowercase form only; the mixed-case
    // variant is the same harmless probe, so a hit is worth one more request.
    sends++;
    const mixed = "JaVaScRiPt:alert(" + canary + ")";
    const resp2 = probe.send(point.withValue(mixed));
    const ev2 = host.oracles.reflection(resp2, canary, ["url-executable"]);
    if (ev2) {
      candidates.push(host.candidate(point.withValue(mixed), "reflected-xss", ev2));
    }
  }
  return candidates;
}
