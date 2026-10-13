/* ---
id: ssrf-blind-oob
name: Blind SSRF via OOB
description: Detects blind SSRF via out-of-band callback correlation and skips honestly without OOB server.
author: GASH contributors
severity: high
tags: [ssrf, oob]
safe: false
deep: false
active: true
requires_auth: false
phase: probe
order: 60
oob: required
api_version: "1.0"
tests: tests/fixtures/ssrf-blind-oob/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/ssrf/ssrf-blind-oob.js
// What: Tier 2 blind-SSRF plugin with mandatory OOB confirmation.
// Why: Reference for the required-OOB discipline; without an OOB server the
//   scheduler skips it and no fake tentative finding is ever produced.

function run(probe, ctx) {
  const points = ctx.injectionPoints();

  const candidates = [];
  for (const point of points) {
    const oob = host.oob.generate("http");
    if (!oob) {
      continue;
    }
    probe.send(point.withValue(oob.url));
    const ev = host.oracles.oob(oob.correlationId, oob.namespace);
    if (ev) {
      candidates.push(host.candidate(point, "ssrf-blind", ev));
    }
  }
  return candidates;
}
