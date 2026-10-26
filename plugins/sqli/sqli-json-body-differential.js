/* ---
id: sqli-json-body-differential
name: SQL Injection in JSON Body (boolean differential)
description: Detects blind boolean SQL injection in JSON API bodies by injecting true/false closure pairs into each discovered JSON field with an explicit application/json content type and comparing them over three repeats.
author: GASH contributors
severity: high
tags: [sqli, injection, json, api, blind]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 62
api_version: "1.0"
tests: tests/fixtures/sqli-json-body-differential/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/sqli/sqli-json-body-differential.js
// What: Tier 2 boolean/differential SQLi plugin for JSON request bodies.
// Why: The query-point differential plugin replays a body point through the
//   urlencoded form builder, so a JSON API never parses it. Injecting the
//   true/false closures into the discovered field and sending it as
//   application/json needs a rebuilt body plus a point-level header. The
//   differential oracle (3/3 masked stability) still decides.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const TRUE_PAY = "1' AND '1'='1";
  const FALSE_PAY = "1' AND '1'='2";
  const jsonContentType = "application/json";
  const maxSends = 60;
  const sendsPerPoint = 7; // 3 true + 3 false + 1 control
  let sends = 0;

  for (const point of points) {
    const loc = String(point.paramLocation || "query").toLowerCase();
    if (loc !== "body") {
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

    const trueResps = [];
    const falseResps = [];
    for (let i = 0; i < 3; i++) {
      sends++;
      trueResps.push(probe.send(raw(TRUE_PAY)));
      sends++;
      falseResps.push(probe.send(raw(FALSE_PAY)));
    }
    // Reflected payloads are noise, not injection proof (same discipline as
    // the query-point differential plugin).
    const echoes = (resps, pay) => resps.some((r) => r && r.body && r.body.indexOf(pay) !== -1);
    if (echoes(trueResps, TRUE_PAY) || echoes(falseResps, FALSE_PAY)) {
      continue;
    }
    sends++;
    const controlResp = probe.send(raw("1"));
    const ev = host.oracles.differential(trueResps, falseResps, controlResp);
    if (ev) {
      candidates.push(host.candidate(point, "sqli-differential", ev));
    }
  }
  return candidates;
}
