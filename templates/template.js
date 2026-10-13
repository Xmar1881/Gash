/* ---
id: template-js
name: Template Js
description: Starter Tier 2 template; detects reflected canary in executable HTML contexts.
author: GASH contributors
severity: high
tags: [xss, client]
safe: true
deep: false
active: false
requires_auth: false
phase: probe
order: 50
api_version: "1.0"
tests: tests/fixtures/template-js/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: templates/template.js
// What: Tier 2 starter template for copy-rename contribution.
// Why: Minimal reflection check behind host.oracles with honest OOB handling.

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
