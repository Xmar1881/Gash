/* ---
id: command-injection-json-body-timing
name: Command Injection via JSON Body Field (timing)
description: Detects blind OS command injection in JSON API body fields by sending shell sleep payloads per discovered field and comparing the measured round-trip series against a neutral-value baseline with a statistical test; the ceiling stays firm.
author: GASH contributors
severity: high
tags: [command-injection, injection, blind, timing, json, api]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 65
api_version: "1.0"
tests: tests/fixtures/command-injection-json-body-timing/
oracle_params:
  min_delay_ms: 5000
  repeats: 3
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/command-injection/command-injection-json-body-timing.js
// What: Tier 2 timing-based command-injection plugin for JSON request bodies.
// Why: The JSON-body OOB plugin needs a reachable callback path; a field that
//   is passed to a shell helper but lives on a segment with no egress stays
//   invisible to it. A sleep payload needs no egress at all, only the receipt
//   of the response, and the delay is measurable in-band. The timing oracle
//   requires three repeats on both branches (Go-measured round trips, never
//   script-invented numbers), so a single slow response can never confirm.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const jsonContentType = "application/json";
  const maxSends = 60;
  const samplesPerPayload = 3;
  // Separator variants: one of them closes whichever shell context the value
  // is spliced into. Every one is a pure delay, never a destructive command.
  const payloads = ["; sleep 6", "| sleep 6", "&& sleep 6", "$(sleep 6)", "`sleep 6`"];
  const sendsPerPoint = samplesPerPayload + payloads.length * samplesPerPayload;
  let sends = 0;

  for (const point of points) {
    if (String(point.paramLocation || "").toLowerCase() !== "body") {
      continue;
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

    // One neutral baseline block serves every payload of this point: the
    // comparison must be between the same endpoint with and without a delay.
    const controlResps = [];
    for (let i = 0; i < samplesPerPayload; i++) {
      sends++;
      controlResps.push(probe.send(raw("gash-control-neutral")));
    }

    let found = false;
    for (let p = 0; p < payloads.length && !found; p++) {
      const delayResps = [];
      for (let i = 0; i < samplesPerPayload; i++) {
        sends++;
        delayResps.push(probe.send(raw(payloads[p])));
      }
      const ev = host.oracles.timing(delayResps, controlResps, {
        min_delay_ms: 5000,
        repeats: samplesPerPayload,
      });
      if (ev) {
        candidates.push(host.candidate(point, "timing", ev));
        found = true;
      }
    }
  }
  return candidates;
}
