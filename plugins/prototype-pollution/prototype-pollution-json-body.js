/* ---
id: prototype-pollution-json-body
name: Prototype Pollution via JSON Body Field
description: Detects JSON body fields whose value is merged into an object without a key allowlist, sending a nested __proto__ object and comparing it against a benign object over three repeats.
author: GASH contributors
severity: high
tags: [prototype-pollution, injection, json, api, differential]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 72
api_version: "1.0"
tests: tests/fixtures/prototype-pollution-json-body/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/prototype-pollution/prototype-pollution-json-body.js
// What: Tier 2 prototype-pollution plugin for JSON request bodies.
// Why: The query-string prototype-pollution check appends `__proto__` to a
//   URL, but modern APIs merge a JSON field into an object server-side; the
//   dangerous shape is the discovered field sent as an OBJECT carrying a
//   `__proto__` member, which only a script can rebuild per field. A stable
//   divergence against a benign object proves the merge gap; an echoing body
//   is reflection and rejects.

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
    // The polluted object adds a prototype member; the benign object carries
    // the same field count so the only difference is the member name.
    const polluted = '{"' + name + '":{"__proto__":{"gashPolluted":"1"}}}';
    const benign = '{"' + name + '":{"gashPolluted":"1"}}';

    const trueResps = [];
    const falseResps = [];
    for (let i = 0; i < 3; i++) {
      sends++;
      trueResps.push(probe.send(raw(polluted)));
      sends++;
      falseResps.push(probe.send(raw(benign)));
    }
    // A body that echoes the injected member is reflection, not a merge.
    if (echoes(trueResps, "__proto__") || echoes(falseResps, "gashPolluted")) {
      continue;
    }
    sends++;
    const controlResp = probe.send(raw('{"' + name + '":"gash-control-neutral"}'));
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
