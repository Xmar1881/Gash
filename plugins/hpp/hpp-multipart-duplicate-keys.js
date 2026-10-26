/* ---
id: hpp-multipart-duplicate-keys
name: HPP Multipart Duplicate-Field Emission (Differential)
description: Detects HTTP parameter pollution in multipart/form-data bodies by emitting a real duplicated field part with a self-built boundary and comparing it against single-part responses.
author: GASH contributors
severity: medium
tags: [hpp, parameter-pollution, injection, differential, multipart]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 67
api_version: "1.0"
tests: tests/fixtures/hpp-multipart-duplicate-keys/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/hpp/hpp-multipart-duplicate-keys.js
// What: Tier 2 HPP plugin emitting a duplicated multipart field part.
// Why: The engine form builder writes exactly one part per field name, so a
//   duplicated multipart name cannot be expressed declaratively; the body, the
//   boundary and the matching Content-Type must all be built by the script.
//   Both branches must be 2xx, so a server that simply rejects the duplicate
//   part is never reported as pollution.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const boundary = "----gashHPPBoundary7f3a";
  const contentType = "multipart/form-data; boundary=" + boundary;
  const maxSends = 60;
  const sendsPerPoint = 7; // 3 single-part + 3 duplicate-part + 1 control
  let sends = 0;

  const part = (name, value) =>
    "--" + boundary + "\r\n" +
    'Content-Disposition: form-data; name="' + name + '"\r\n\r\n' +
    value + "\r\n";
  const singleBody = (name, value) => part(name, value) + "--" + boundary + "--\r\n";
  const duplicateBody = (name, first, second) =>
    part(name, first) + part(name, second) + "--" + boundary + "--\r\n";
  const ok2xx = (r) => r && r.status >= 200 && r.status < 300;

  for (const point of points) {
    const loc = String(point.paramLocation || "query").toLowerCase();
    if (loc !== "body") {
      continue;
    }
    if (!point.paramName) {
      continue;
    }
    if (sends + sendsPerPoint > maxSends) {
      break;
    }
    const name = point.paramName;
    const raw = (body) => ({
      url: point.url,
      method: point.method,
      paramName: "",
      paramLocation: "body",
      value: body,
      headers: { "Content-Type": contentType },
    });

    const singleResps = [];
    for (let i = 0; i < 3; i++) {
      sends++;
      singleResps.push(probe.send(raw(singleBody(name, "1"))));
    }
    const dupResps = [];
    for (let i = 0; i < 3; i++) {
      sends++;
      dupResps.push(probe.send(raw(duplicateBody(name, "1", "2"))));
    }
    // A parser rejecting the duplicate part is a rejection, not pollution.
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
    const controlResp = probe.send(raw(singleBody(name, "gash-control-neutral")));
    const ev = host.oracles.differential(dupResps, singleResps, controlResp);
    if (ev) {
      candidates.push(host.candidate(point, "differential", ev));
    }
  }
  return candidates;
}
