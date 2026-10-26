/* ---
id: open-redirect-json-body
name: Open Redirect via JSON Body Field
description: Detects unvalidated redirects triggered by a JSON body field by injecting a canary host into each discovered field with an explicit application/json content type and parsing the real Location header against a neutral-value control.
author: GASH contributors
severity: medium
tags: [redirect, open-redirect, json, client]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 68
api_version: "1.0"
tests: tests/fixtures/open-redirect-json-body/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/redirect/open-redirect-json-body.js
// What: Tier 2 open-redirect plugin for JSON request bodies.
// Why: Tier 1 declares one static body per file, so a JSON API field that
//   feeds a redirect target cannot be exercised field by field. The body is
//   rebuilt around the discovered field and sent as application/json, and the
//   real Location header is compared against a neutral-value control.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const jsonContentType = "application/json";
  const maxSends = 40;
  const sendsPerPoint = 2; // one probe + one control
  let sends = 0;

  for (const point of points) {
    const loc = String(point.paramLocation || "query").toLowerCase();
    if (loc !== "body") {
      continue; // JSON body fields only
    }
    if (!point.paramName) {
      continue;
    }
    if (sends + sendsPerPoint > maxSends) {
      break;
    }
    const name = point.paramName;
    const payloadHost = probe.canary() + ".gash-redirect.example";
    const raw = (value) => ({
      url: point.url,
      method: point.method,
      paramName: "",
      paramLocation: "body",
      value: '{"' + name + '":"' + value + '"}',
      headers: { "Content-Type": jsonContentType },
    });

    sends++;
    const controlResp = probe.send(raw("gash-control-neutral"));
    sends++;
    const resp = probe.send(raw("https://" + payloadHost + "/landing"));

    // Control discipline: a neutral value must never produce a redirect to the
    // payload host. Without this gate a server that echoes the field into a
    // fixed target could look like a finding.
    const controlLocation = controlResp && controlResp.headers
      ? String(controlResp.headers["Location"] || controlResp.headers["location"] || "")
      : "";
    if (controlLocation.indexOf(payloadHost) !== -1) {
      continue;
    }
    const ev = host.oracles.redirect(resp, payloadHost);
    if (ev) {
      candidates.push(host.candidate(point, "open-redirect", ev));
    }
  }
  return candidates;
}
