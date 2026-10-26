/* ---
id: graphql-batch-abuse
name: GraphQL Batch Query Abuse
description: Detects GraphQL endpoints that accept batched operations, letting one HTTP request run many operations past per-request rate limits, depth guards, and cost analysis.
author: GASH contributors
severity: medium
tags: [graphql, dos, api, rate-limit, differential]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 74
api_version: "1.0"
tests: tests/fixtures/graphql-batch-abuse/
oracle_params:
  confidence_ceiling: firm
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/graphql-batch-abuse.js
// What: Tier 2 GraphQL batch-abuse plugin.
// Why: A batch is a JSON *array* of operations; Tier 1 declares a single static
//   body, so it can send either one operation or a fixed literal, never a
//   repeatable batch built per endpoint. Accepting the batch is a hardening gap
//   rather than an exploitable flaw, so the plugin declares
//   `confidence_ceiling: firm` in oracle_params: the differential oracle proves
//   the divergence, and the ceiling keeps the finding honest.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const jsonContentType = "application/json";
  const operation = '{"query":"{__typename}"}';
  const batchBody = "[" + operation + "," + operation + "," + operation + "]";
  const singleBody = operation;
  const controlBody = '{"query":"{__typename gashControlProbeField}"}';
  const maxSends = 60;
  const sendsPerPoint = 7; // 3 single + 3 batch + 1 control
  let sends = 0;

  const isGraphQLPoint = (point) => {
    const url = String(point.url || "").toLowerCase();
    return url.indexOf("graphql") !== -1 || url.indexOf("/gql") !== -1;
  };
  const looksLikeArray = (r) => r && typeof r.body === "string" && r.body.replace(/^\s+/, "").charAt(0) === "[";
  const looksLikeObject = (r) => r && typeof r.body === "string" && r.body.replace(/^\s+/, "").charAt(0) === "{";
  const ok2xx = (r) => r && r.status >= 200 && r.status < 300;

  for (const point of points) {
    if (!isGraphQLPoint(point)) {
      continue; // batch plumbing only exists on a GraphQL transport
    }
    if (sends + sendsPerPoint > maxSends) {
      break;
    }
    const raw = (body) => ({
      url: point.url,
      method: "POST",
      paramName: "",
      paramLocation: "body",
      value: body,
      headers: { "Content-Type": jsonContentType },
    });

    const singleResps = [];
    const batchResps = [];
    for (let i = 0; i < 3; i++) {
      sends++;
      singleResps.push(probe.send(raw(singleBody)));
      sends++;
      batchResps.push(probe.send(raw(batchBody)));
    }
    // Gate: the single operation must answer as an object and the batch as an
    // array. Only then did the server actually execute a batch instead of
    // rejecting it, which is what this plugin claims.
    let accepted = true;
    for (const r of singleResps) {
      if (!ok2xx(r) || !looksLikeObject(r)) {
        accepted = false;
        break;
      }
    }
    for (const r of batchResps) {
      if (!ok2xx(r) || !looksLikeArray(r)) {
        accepted = false;
        break;
      }
    }
    if (!accepted) {
      continue;
    }
    sends++;
    const controlResp = probe.send(raw(controlBody));
    const ev = host.oracles.differential(batchResps, singleResps, controlResp);
    if (ev) {
      candidates.push(host.candidate(point, "differential", ev));
    }
  }
  return candidates;
}
