/* ---
id: hpp-duplicate-emission
name: HPP Duplicate-Key Emission (Differential)
description: Detects HTTP parameter pollution via real duplicated-key emission (id=1&id=2) and differential comparison against single-value responses.
author: GASH contributors
severity: medium
tags: [hpp, parameter-pollution, injection, differential]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 64
api_version: "1.0"
tests: tests/fixtures/hpp-duplicate-emission/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/hpp/hpp-duplicate-emission.js
// What: Tier 2 HPP plugin emitting real duplicated keys (id=1&id=2).
// Why: Tier 1 models pollution as true/false value divergence (approximation);
//   this plugin proves server-side parsing confusion with native duplicate-key
//   emission, compared via the differential oracle (3/3 masked stability).
//   No new sandbox surface: only probe.send + ctx surface + host.oracles.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const maxSends = 60;
  const sendsPerPoint = 7; // 3 single + 3 duplicate + 1 control
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
    const singleResps = [];
    for (let i = 0; i < 3; i++) {
      sends++;
      singleResps.push(probe.send(point.withValue("1")));
    }
    const dupResps = [];
    for (let i = 0; i < 3; i++) {
      let dupPoint;
      if (loc === "body") {
        const body = encodeURIComponent(point.paramName) + "=1&" + encodeURIComponent(point.paramName) + "=2";
        dupPoint = {url: point.url, method: point.method, paramName: "", paramLocation: point.paramLocation, value: body};
      } else {
        const base = String(point.url).split("?")[0].split("#")[0];
        const key = encodeURIComponent(point.paramName);
        const dupUrl = base + "?" + key + "=1&" + key + "=2";
        dupPoint = {url: dupUrl, method: point.method, paramName: "", paramLocation: point.paramLocation, value: ""};
      }
      sends++;
      dupResps.push(probe.send(dupPoint));
    }
    sends++;
    const controlResp = probe.send(point.withValue("gash-control-neutral"));
    const ev = host.oracles.differential(dupResps, singleResps, controlResp);
    if (ev) {
      candidates.push(host.candidate(point, "differential", ev));
    }
  }
  return candidates;
}
