/* ---
id: lfi-json-body
name: Path Traversal / LFI via JSON Body Field
description: Detects path traversal and local file inclusion when a JSON API body field is used as a file path, injecting traversal payloads with an explicit application/json content type and requiring real file-content signatures absent from the control.
author: GASH contributors
severity: high
tags: [path-traversal, lfi, file-access, injection, json]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 73
api_version: "1.0"
tests: tests/fixtures/lfi-json-body/
oracle_params:
  mode: path_traversal
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/lfi-json-body.js
// What: Tier 2 path traversal / LFI plugin for JSON request bodies.
// Why: Tier 1 path traversal injects into query parameter names, so a JSON API
//   field that is used as a file path is never exercised: the payload has to be
//   built into a JSON object and sent with an explicit application/json content
//   type. The signature family (real file content) comes from the plugin-level
//   oracle_params block, so the fixture runner applies exactly the same mode
//   the live scan uses.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const jsonContentType = "application/json";
  // Traversal depths and encodings; the target file is a signature source only,
  // never read for exfiltration.
  const payloads = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..\\..\\..\\..\\windows\\win.ini",
  ];
  const maxSends = 60;
  const sendsPerPoint = payloads.length * 2; // probe + control per payload
  let sends = 0;

  for (const point of points) {
    const loc = String(point.paramLocation || "query").toLowerCase();
    if (loc !== "body") {
      continue; // file-path fields are body fields here
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
    let found = false;
    for (const payload of payloads) {
      if (found) {
        break;
      }
      sends++;
      const resp = probe.send(raw(payload));
      sends++;
      // Neutral value in the same field: a file signature here means the page
      // leaks it anyway and the traversal is not the cause.
      const controlResp = probe.send(raw("gash-control-neutral"));
      const ev = host.oracles.error(resp, controlResp);
      if (ev) {
        candidates.push(host.candidate(point, "error", ev));
        found = true;
      }
    }
  }
  return candidates;
}
