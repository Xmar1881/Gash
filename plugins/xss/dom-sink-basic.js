/* ---
id: dom-sink-basic
name: DOM Sink (static, headless-free)
description: Detects static DOM sinks with URL-controlled sources via the execution oracle without a browser. Headless absent, so the ceiling is firm.
author: Gash contributors
severity: medium
tags: [xss, dom, client]
safe: true
deep: false
active: false
requires_auth: false
phase: probe
order: 45
api_version: "1.0"
tests: tests/fixtures/dom-sink-basic/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / Gash contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/xss/dom-sink-basic.js
// What: Tier 2 static DOM sink scanner backed by ExecutionOracle.
// Why: Browser-free static sink/source analysis caps at firm; confirmed
//   requires the headless build (documented BLOCKED without browser deps).

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  for (const point of points) {
    const resp = probe.send(point.withValue("gash-dom-probe"));
    const ev = host.oracles.execution(resp);
    if (ev) {
      candidates.push(host.candidate(point, "dom-xss", ev));
    }
  }
  return candidates;
}
