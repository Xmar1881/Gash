/* ---
id: hpp-json-duplicate-keys
name: HPP JSON Duplicate-Key Emission (Differential)
description: Detects HTTP parameter pollution in JSON bodies by emitting a real duplicated JSON key ({"id":1,"id":2}) with an explicit application/json content type and comparing it against single-key responses.
author: GASH contributors
severity: medium
tags: [hpp, parameter-pollution, injection, differential, json]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 65
api_version: "1.0"
tests: tests/fixtures/hpp-json-duplicate-keys/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/hpp/hpp-json-duplicate-keys.js
// What: Tier 2 HPP plugin emitting duplicate JSON keys with a JSON body.
// Why: Tier 1 declares one body payload per parameter and the urlencoded form
//   builder cannot express a duplicated key; a JSON object literal needs the
//   raw body plus an explicit application/json content type, which only a
//   point-level header can carry. The differential oracle still decides.
//   Guard: both branches must be 2xx, so a strict parser that merely rejects
//   the duplicate key (400/422) is never reported as pollution.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const jsonContentType = "application/json";
  const maxSends = 60;
  const sendsPerPoint = 7; // 3 single + 3 duplicate + 1 control
  let sends = 0;

  const ok2xx = (r) => r && r.status >= 200 && r.status < 300;

  for (const point of points) {
    const loc = String(point.paramLocation || "query").toLowerCase();
    if (loc !== "body") {
      continue; // duplicated JSON keys only apply to request bodies
    }
    if (!point.paramName) {
      continue;
    }
    if (sends + sendsPerPoint > maxSends) {
      break;
    }
    const key = point.paramName;
    const raw = (body) => ({
      url: point.url,
      method: point.method,
      paramName: "",
      paramLocation: "body",
      value: body,
      headers: { "Content-Type": jsonContentType },
    });

    const singleResps = [];
    for (let i = 0; i < 3; i++) {
      sends++;
      singleResps.push(probe.send(raw('{"' + key + '":1}')));
    }
    const dupResps = [];
    for (let i = 0; i < 3; i++) {
      sends++;
      dupResps.push(probe.send(raw('{"' + key + '":1,"' + key + '":2}')));
    }
    // Both branches must have been accepted by the parser: a strict JSON
    // parser rejecting the duplicate key is a rejection, not pollution.
    for (const r of singleResps) {
      if (!ok2xx(r)) {
        singleResps.length = 0;
        break;
      }
    }
    for (const r of dupResps) {
      if (!ok2xx(r)) {
        dupResps.length = 0;
        break;
      }
    }
    if (singleResps.length !== 3 || dupResps.length !== 3) {
      continue;
    }
    sends++;
    const controlResp = probe.send(raw('{"' + key + '":"gash-control-neutral"}'));
    const ev = host.oracles.differential(dupResps, singleResps, controlResp);
    if (ev) {
      candidates.push(host.candidate(point, "differential", ev));
    }
  }
  return candidates;
}
