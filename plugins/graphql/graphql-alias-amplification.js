/* ---
id: graphql-alias-amplification
name: GraphQL Alias Amplification (resource abuse)
description: Detects GraphQL alias amplification by sending one aliased batch that repeats the same field many times and comparing its stable response against the single-field response over three repeats; the divergence is capped at firm because acceptance proves the gap, not the amplification factor.
author: GASH contributors
severity: medium
tags: [graphql, dos, resource-abuse, differential, api]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 69
api_version: "1.0"
tests: tests/fixtures/graphql-alias-amplification/
oracle_params:
  confidence_ceiling: firm
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/graphql/graphql-alias-amplification.js
// What: Tier 2 GraphQL alias-amplification plugin.
// Why: The batch plugin proves that an operation ARRAY is accepted; alias
//   amplification is a different primitive: one operation whose field is
//   repeated under many aliases, which bypasses naive depth counting while
//   multiplying resolver work. Proving it needs a generated document (an
//   aliased selection set built at runtime) compared against the single-field
//   document over three repeats, which a static Tier 1 body cannot express.
//   The ceiling stays firm: acceptance proves the gap, not the amplification
//   factor actually reached.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const jsonContentType = "application/json";
  const maxSends = 60;
  let sends = 0;
  const aliasCount = 25;

  // One aliased selection set: same field, 25 distinct aliases.
  let amplified = "{";
  for (let i = 0; i < aliasCount; i++) {
    amplified += " a" + i + ":__typename";
  }
  amplified += " }";
  const single = "{ __typename }";

  for (const point of points) {
    if (!point.paramName) {
      continue;
    }
    if (String(point.paramLocation || "").toLowerCase() !== "body") {
      continue;
    }
    if (sends + 7 > maxSends) {
      break;
    }
    const name = point.paramName;
    const raw = (doc) => ({
      url: point.url,
      method: point.method,
      paramName: "",
      paramLocation: "body",
      value: '{"' + name + '":"' + doc + '"}',
      headers: { "Content-Type": jsonContentType },
    });

    const trueResps = [];
    const falseResps = [];
    for (let i = 0; i < 3; i++) {
      sends++;
      trueResps.push(probe.send(raw(amplified)));
      sends++;
      falseResps.push(probe.send(raw(single)));
    }
    // A body that echoes the aliased document is reflection, not execution.
    if (echoes(trueResps, "a24:__typename")) {
      continue;
    }
    sends++;
    const controlResp = probe.send(raw('{"' + name + '":"{ __typename }"}'));
    const ev = host.oracles.differential(trueResps, falseResps, controlResp);
    if (ev) {
      candidates.push(host.candidate(point, "differential", ev));
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
