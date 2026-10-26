/* ---
id: command-injection-json-body-error
name: Command Injection via JSON Body Field (error-based)
description: Detects blind OS command injection in JSON API body fields by sending shell syntax-error payloads per field and comparing the command-error signature against a neutral-value control.
author: GASH contributors
severity: high
tags: [command-injection, injection, json, api, error]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 76
api_version: "1.0"
tests: tests/fixtures/command-injection-json-body-error/
oracle_params:
  mode: generic_error
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/command-injection/command-injection-json-body-error.js
// What: Tier 2 error-based command-injection plugin for JSON request bodies.
// Why: The JSON-body OOB and timing plugins need egress and a measurable
//   delay. An endpoint that shells out but has no egress and a small command
//   budget is invisible to both, while a shell that is handed a broken
//   fragment still reports its own syntax error in the response. Payloads are
//   deliberately inert fragments (an unterminated substitution or an
//   incomplete operator): they provoke the interpreter's complaint without
//   running anything.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const jsonContentType = "application/json";
  const maxSends = 40;
  let sends = 0;
  const payloads = ["$(", "; ;", "`", "| |", "&& (", "; if"];

  for (const point of points) {
    if (String(point.paramLocation || "").toLowerCase() !== "body") {
      continue;
    }
    if (!point.paramName) {
      continue;
    }
    if (sends + payloads.length * 2 > maxSends) {
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
    for (let i = 0; i < payloads.length && !found; i++) {
      sends++;
      const resp = probe.send(raw(payloads[i]));
      sends++;
      // A neutral value in the same field: an interpreter error that also
      // appears here is the endpoint's normal behaviour, not injection.
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
