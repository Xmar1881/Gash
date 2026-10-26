/* ---
id: mass-assignment-nested-json
name: Mass Assignment via Nested JSON Object
description: Detects mass assignment when a scalar JSON body field is bound as an object, sending a privileged-field object and comparing it against a non-binding object over three repeats; the divergence is capped at firm because binding proves the gap, not an escalation.
author: GASH contributors
severity: medium
tags: [mass-assignment, authorization, differential, json, api]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 68
api_version: "1.0"
tests: tests/fixtures/mass-assignment-nested-json/
oracle_params:
  confidence_ceiling: firm
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/mass-assignment/mass-assignment-nested-json.js
// What: Tier 2 mass-assignment plugin for JSON request bodies.
// Why: The query/form mass-assignment check can only append a scalar field to
//   a fixed body. The JSON shape under test is different: the discovered field
//   is sent as an OBJECT carrying fields the API never advertises, which is how
//   a loose binder (model binding, JSON-to-struct unmarshal without an allow
//   list) picks up a privileged field. The privileged object and a
//   non-binding object are compared over three repeats, and the ceiling stays
//   firm because a stable divergence proves the binding gap, not that the
//   privileged value took effect.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const jsonContentType = "application/json";
  const maxSends = 60;
  let sends = 0;

  for (const point of points) {
    if (String(point.paramLocation || "").toLowerCase() !== "body") {
      continue;
    }
    if (!point.paramName) {
      continue;
    }
    if (sends + 7 > maxSends) {
      break;
    }
    const name = point.paramName;
    const raw = (body) => ({
      url: point.url,
      method: point.method,
      paramName: "",
      paramLocation: "body",
      value: body,
      headers: { "Content-Type": jsonContentType },
    });
    const privileged = '{"' + name + '":{"role":"admin","is_admin":true}}';
    const benign = '{"' + name + '":{"role":"gash-no-such-role-3f91"}}';

    let found = false;
    for (let attempt = 0; attempt < 2 && !found; attempt++) {
      if (sends + 7 > maxSends) {
        break;
      }
      const trueResps = [];
      const falseResps = [];
      for (let i = 0; i < 3; i++) {
        sends++;
        trueResps.push(probe.send(raw(privileged)));
        sends++;
        falseResps.push(probe.send(raw(benign)));
      }
      // A body that echoes the privileged field is reflection, not binding.
      if (echoes(trueResps, "admin") || echoes(trueResps, "is_admin")) {
        continue;
      }
      sends++;
      const controlResp = probe.send(raw('{"' + name + '":"gash-control-neutral"}'));
      const ev = host.oracles.differential(trueResps, falseResps, controlResp);
      if (ev) {
        candidates.push(host.candidate(point, "differential", ev));
        found = true;
      }
    }
  }
  return candidates;
}

// echoes reports whether any response body carries the needle verbatim.
function echoes(responses, needle) {
  for (let i = 0; i < responses.length; i++) {
    const r = responses[i];
    if (r && r.body && String(r.body).indexOf(needle) !== -1) {
      return true;
    }
  }
  return false;
}
