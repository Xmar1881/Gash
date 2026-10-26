/* ---
id: nosql-injection-differential-json-body
name: NoSQL Operator Injection in JSON Body (differential)
description: Detects MongoDB operator injection when a JSON API body field is passed straight into a query document, sending an always-true operator object and comparing it against a non-matching literal over three repeats.
author: GASH contributors
severity: high
tags: [nosql, injection, differential, json, api]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 83
api_version: "1.0"
tests: tests/fixtures/nosql-injection-differential-json-body/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/nosql/nosql-injection-differential-json-body.js
// What: Tier 2 NoSQL operator-injection plugin for JSON request bodies.
// Why: The query-point NoSQL plugins cannot reach a JSON API: the operator has
//   to be built into the object around the discovered field and sent as
//   application/json. An always-true operator object ($ne with an unlikely
//   value, $gt with an empty bound) is compared against a literal that cannot
//   match the collection, over three repeats, so an ordinary "not found" page
//   never confirms. A body that echoes the value is noise, not injection proof.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const jsonContentType = "application/json";
  const falseValue = "gash-no-such-entry-9f3a";
  // Always-true operator objects versus one non-matching literal.
  const operators = [
    (name) => '{"' + name + '":{"$ne":"gash-ne-canary-7c1d"}}',
    (name) => '{"' + name + '":{"$gt":""}}',
  ];
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
    const method = point.method || "POST";
    const raw = (body) => ({
      url: point.url,
      method: method,
      paramName: "",
      paramLocation: "body",
      value: body,
      headers: { "Content-Type": jsonContentType },
    });
    const falseBody = '{"' + name + '":"' + falseValue + '"}';
    let found = false;
    for (const op of operators) {
      if (found || sends + 7 > maxSends) {
        break;
      }
      const trueResps = [];
      const falseResps = [];
      for (let i = 0; i < 3; i++) {
        sends++;
        trueResps.push(probe.send(raw(op(name))));
        sends++;
        falseResps.push(probe.send(raw(falseBody)));
      }
      // A body that simply echoes our operator or value is not injection proof.
      const echoes = (resps, needle) =>
        resps.some((r) => r && r.body && r.body.indexOf(needle) !== -1);
      if (echoes(trueResps, "$ne") || echoes(trueResps, "$gt") || echoes(falseResps, falseValue)) {
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
