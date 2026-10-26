/* ---
id: xpath-injection-json-body
name: XPath Injection in JSON Body (error-based)
description: Detects XPath injection in JSON API bodies by injecting a predicate-closing syntax probe into each discovered JSON field with an explicit application/json content type and matching XML/query parser error signatures against a neutral-value control.
author: GASH contributors
severity: high
tags: [xpath, injection, error-signature, json, api]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 73
api_version: "1.0"
tests: tests/fixtures/xpath-injection-json-body/
oracle_params:
  mode: xpath
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/xpath/xpath-injection-json-body.js
// What: Tier 2 error-based XPath injection plugin for JSON request bodies.
// Why: The query-point XPath plugin declares one static query string; a JSON
//   API needs the syntax probe built into the object around the discovered
//   field and sent as application/json, which the urlencoded form builder never
//   produces. The probe is a harmless predicate-closing attempt (no file read,
//   no DOS); the oracle matches parser error signatures and requires absence in
//   the neutral control, so a reflected payload alone never confirms. The
//   signature family is declared once in oracle_params.mode.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  // Harmless predicate-closing syntax probes (single quotes keep JSON valid).
  const payloads = ["x'] | //* | a['", "1' or '1'='1"];
  const jsonContentType = "application/json";
  const maxSends = 40;
  let sends = 0;

  for (const point of points) {
    if (String(point.paramLocation || "").toLowerCase() !== "body") {
      continue;
    }
    if (!point.paramName) {
      continue;
    }
    if (sends + 2 > maxSends) {
      break;
    }
    const name = point.paramName;
    const method = point.method || "POST";
    const raw = (value) => ({
      url: point.url,
      method: method,
      paramName: "",
      paramLocation: "body",
      value: '{"' + name + '":"' + value + '"}',
      headers: { "Content-Type": jsonContentType },
    });
    sends++;
    // A neutral value in the same field: the signature must be absent here.
    const controlResp = probe.send(raw("gash-control-neutral"));
    for (const payload of payloads) {
      if (sends + 1 > maxSends) {
        break;
      }
      sends++;
      const resp = probe.send(raw(payload));
      const ev = host.oracles.error(resp, controlResp);
      if (ev) {
        candidates.push(host.candidate(point, "error", ev));
        break;
      }
    }
  }
  return candidates;
}
