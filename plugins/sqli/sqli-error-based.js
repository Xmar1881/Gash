/* ---
id: sqli-error-based
name: SQLi Error Based
description: Detects error-based SQL injection via database signature match plus absent-in-control proof.
author: GASH contributors
severity: high
tags: [sqli, injection]
safe: true
deep: false
active: false
requires_auth: false
phase: probe
order: 50
api_version: "1.0"
tests: tests/fixtures/sqli-error-based/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/sqli/sqli-error-based.js
// What: Tier 2 error-based SQLi plugin backed by ErrorSignatureOracle.
// Why: Reference for signature-plus-control evidence; a signature that also
//   appears in the control response must reject instead of confirming.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const payloads = ["' AND 1=CONVERT(int,@@version)--", "' OR '1'='1"];

  const candidates = [];
  for (const point of points) {
    const controlResp = probe.send(point.withValue("gash-control"));
    for (const payload of payloads) {
      const resp = probe.send(point.withValue(payload));
      const ev = host.oracles.error(resp, controlResp);
      if (ev) {
        candidates.push(host.candidate(point, "sqli-error", ev));
        break;
      }
    }
  }
  return candidates;
}
