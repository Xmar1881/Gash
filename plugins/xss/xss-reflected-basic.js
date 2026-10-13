/* ---
id: xss-reflected-basic
name: Reflected XSS (basic contexts)
description: Detects reflected XSS via canary reflection in executable HTML contexts with control comparison.
author: GASH contributors
severity: high
tags: [xss, client]
safe: true
deep: false
active: false
requires_auth: false
phase: probe
order: 40
api_version: "1.0"
tests: tests/fixtures/xss-reflected-basic/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/xss/xss-reflected-basic.js
// What: Tier 2 reflected-XSS plugin following the spec section 4.6 JS example.
// Why: Reference for ReflectionOracle in basic contexts; control comparison keeps
//   text-only reflection at tentative while executable reflection confirms.

function run(probe, ctx) {
  const points = ctx.injectionPoints();

  const candidates = [];
  for (const point of points) {
    const canary = probe.canary();
    const resp = probe.send(point.withValue(canary));
    const ev = host.oracles.reflection(resp, canary, ["html", "attr", "script"]);
    if (ev) {
      candidates.push(host.candidate(point, "reflected-xss", ev));
    }
  }
  return candidates;
}
