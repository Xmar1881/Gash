/* ---
id: nosql-injection-timing-json-body
name: NoSQL Injection Time-Based in JSON Body (Blind)
description: Detects blind time-based NoSQL injection in JSON API bodies by injecting MongoDB $where sleep and busy-loop expressions into the request object and comparing measured latency against a neutral $where baseline.
author: GASH contributors
severity: high
tags: [nosql, injection, blind, timing, json, api]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 82
api_version: "1.0"
tests: tests/fixtures/nosql-injection-timing-json-body/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/nosql/nosql-injection-timing-json-body.js
// What: Tier 2 time-based blind NoSQL injection plugin for JSON request bodies.
// Why: The query-string NoSQL timing plugin cannot reach a JSON API. A $where
//   operator has to sit at the top level of the request object, which needs the
//   body rebuilt and sent with an explicit application/json content type. When
//   the endpoint answers identically regardless of the operator, only the
//   latency of the injected request differs, so a neutral $where baseline is
//   measured first (ceiling stays firm: timing carries no confirmation).

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const payloads = [
    "sleep(5000)",
    "var d=new Date(); do {var d2=new Date();} while(d2-d<5000);",
  ];
  const jsonContentType = "application/json";
  const repeats = 3;
  const minDelayMs = 5000;
  const maxSends = 60;
  const sendsPerPoint = repeats + payloads.length * repeats;
  let sends = 0;
  const seen = {};

  for (const point of points) {
    if (String(point.paramLocation || "").toLowerCase() !== "body") {
      continue;
    }
    const base = String(point.url || "").split("#")[0];
    if (!base || seen[base]) {
      continue; // one timing sequence per URL
    }
    seen[base] = true;
    if (sends + sendsPerPoint > maxSends) {
      break;
    }
    const method = point.method || "POST";
    const raw = (expr) => ({
      url: base,
      method: method,
      paramName: "",
      paramLocation: "body",
      value: '{"$where":"' + expr + '"}',
      headers: { "Content-Type": jsonContentType },
    });

    // Baseline latencies first: a $where that never sleeps. A slow endpoint
    // must not look like an injected delay.
    const controlResps = [];
    for (let i = 0; i < repeats; i++) {
      sends++;
      controlResps.push(probe.send(raw("false")));
    }
    for (const payload of payloads) {
      const delayResps = [];
      for (let i = 0; i < repeats; i++) {
        sends++;
        delayResps.push(probe.send(raw(payload)));
      }
      const ev = host.oracles.timing(delayResps, controlResps, {
        min_delay_ms: minDelayMs,
        repeats: repeats,
      });
      if (ev) {
        candidates.push(host.candidate(point, "timing", ev));
        break;
      }
    }
  }
  return candidates;
}
