/* ---
id: sqli-boolean-differential
name: SQLi Boolean Differential
description: Detects boolean-based SQL injection via true/false/control triple with three repeats.
author: GASH contributors
severity: high
tags: [sqli, injection]
safe: true
deep: false
active: false
requires_auth: false
phase: probe
order: 51
api_version: "1.0"
tests: tests/fixtures/sqli-boolean-differential/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/sqli/sqli-boolean-differential.js
// What: Tier 2 boolean/differential SQLi plugin backed by DifferentialOracle.
// Why: Reference for N-equals-3 plus control discipline; unstable differentials
//   reject outright instead of emitting tentative noise.

function run(probe, ctx) {
  const points = ctx.injectionPoints();

  const candidates = [];
  for (const point of points) {
    const trueResps = [];
    const falseResps = [];
    for (let i = 0; i < 3; i++) {
      trueResps.push(probe.send(point.withValue("1' AND '1'='1")));
      falseResps.push(probe.send(point.withValue("1' AND '1'='2")));
    }
    const controlResp = probe.send(point.withValue("1"));
    const ev = host.oracles.differential(trueResps, falseResps, controlResp);
    if (ev) {
      candidates.push(host.candidate(point, "sqli-differential", ev));
    }
  }
  return candidates;
}
