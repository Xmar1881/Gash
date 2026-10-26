/* ---
id: sqli-json-body-error
name: SQL Injection in JSON Body (error-based)
description: Detects SQL injection in JSON API bodies by injecting a closure payload into each discovered JSON field with an explicit application/json content type and comparing database error signatures against a neutral-value control.
author: GASH contributors
severity: high
tags: [sqli, injection, json, api]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 61
api_version: "1.0"
tests: tests/fixtures/sqli-json-body-error/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/sqli/sqli-json-body-error.js
// What: Tier 2 error-based SQLi plugin for JSON request bodies.
// Why: Tier 1 declares one static body per file, so it can only test a
//   hardcoded JSON shape. Discovering a body point and injecting the payload
//   into that exact field needs a script: the body is rebuilt per field and
//   sent with an explicit application/json content type, which the urlencoded
//   form builder never produces. No new sandbox surface: only probe.send plus
//   the ctx surface plus host.oracles.error plus host.candidate.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  // JSON-string-safe closures: a bare double quote would break the object.
  const payloads = ["'", "1'", "' OR '1'='1"];
  const jsonContentType = "application/json";
  const maxSends = 60;
  const sendsPerPoint = payloads.length * 2; // probe + control per payload
  let sends = 0;

  for (const point of points) {
    const loc = String(point.paramLocation || "query").toLowerCase();
    if (loc !== "body") {
      continue; // JSON field injection only applies to request bodies
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
    let found = false;
    for (const payload of payloads) {
      if (found) {
        break;
      }
      sends++;
      const resp = probe.send(raw(payload));
      sends++;
      // A neutral value in the same field: the signature must be absent here.
      const controlResp = probe.send(raw("1"));
      const ev = host.oracles.error(resp, controlResp);
      if (ev) {
        candidates.push(host.candidate(point, "sqli-error", ev));
        found = true;
      }
    }
  }
  return candidates;
}
