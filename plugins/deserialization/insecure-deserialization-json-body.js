/* ---
id: insecure-deserialization-json-body
name: Insecure Deserialization via JSON Body Field (error signatures)
description: Detects insecure deserialization when a JSON API body field is handed to a native deserializer, injecting serialized-object markers and grading language-specific deserialization error signatures against a neutral-value control.
author: GASH contributors
severity: high
tags: [deserialization, injection, json, api, error-signature]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 79
api_version: "1.0"
tests: tests/fixtures/insecure-deserialization-json-body/
oracle_params:
  mode: deserialization
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/deserialization/insecure-deserialization-json-body.js
// What: Tier 2 deserialization plugin for JSON request bodies.
// Why: A JSON API field that is base64-decoded and handed to a native
//   deserializer (Java ObjectInputStream, PHP unserialize, Python pickle) is
//   not reachable from the query-point plugin. The payloads here are inert
//   serialization markers, never a gadget chain: the signature family is
//   declared once in oracle_params, so the fixture runner grades the same mode
//   a live scan uses. Ceiling stays firm (no gadget execution is attempted).

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const jsonContentType = "application/json";
  // Serialized-object markers per runtime; inert, no gadget chain.
  const payloads = [
    "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", // Java stream magic (base64)
    "O:8:\"stdClass\":0:{}",                   // PHP serialized object
    "gASVCAAAAAAAAACMCmRjLmRpc3BhdGNo",     // Python pickle protocol 4
    "AAEAAAD/////AQAAAAAAAAAMAgAAAHNTeXN0ZW0u", // .NET BinaryFormatter header
  ];
  const maxSends = 60;
  const sendsPerPoint = payloads.length * 2; // probe + control per payload
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
      value: '{"' + name + '":"' + value.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"}',
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
      // Neutral value in the same field: a deserialization signature there
      // means the endpoint leaks it regardless of our payload.
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
