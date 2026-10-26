/* ---
id: ldap-injection-json-body-timing
name: LDAP Injection via JSON Body Field (timing)
description: Detects blind LDAP injection when a JSON API body field is spliced into a directory filter, sending a heavy wildcard-filter closure per field and comparing the measured round-trip series against a neutral baseline; the ceiling stays firm.
author: GASH contributors
severity: medium
tags: [ldap, injection, blind, timing, json, api]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 74
api_version: "1.0"
tests: tests/fixtures/ldap-injection-json-body-timing/
oracle_params:
  min_delay_ms: 5000
  repeats: 3
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/ldap/ldap-injection-json-body-timing.js
// What: Tier 2 blind LDAP-injection plugin (JSON body, timing).
// Why: The differential JSON plugin needs the backend to answer the two
//   branches differently; the OOB JSON plugin needs a callback path. A
//   directory that returns the same "invalid credentials" page and has no
//   egress is invisible to both. A filter closure that expands into many
//   candidate evaluations costs measurable time, and that delay is observable
//   in-band. Three repeats on both branches are required, so one slow response
//   can never confirm; the ceiling stays firm.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const jsonContentType = "application/json";
  const maxSends = 60;
  const samplesPerPayload = 3;
  // Filter closures that force a wide candidate evaluation. Each one only
  // widens the search; none of them reads an attribute back.
  const payloads = [
    "*)(cn=*)(|(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*))",
    "*)(uid=*)(|(uid=*)(uid=*)(uid=*)(uid=*)(uid=*)(uid=*))",
  ];
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

    // One neutral baseline block serves every payload of this point.
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
