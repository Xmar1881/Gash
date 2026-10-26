/* ---
id: xss-reflected-json-body
name: Reflected XSS via JSON Body Field
description: Detects reflected XSS when a JSON API body field is echoed into an executable HTML context, injecting a parser-recognized execution payload per discovered field with an explicit application/json content type.
author: GASH contributors
severity: high
tags: [xss, injection, json, api, client]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 69
api_version: "1.0"
tests: tests/fixtures/xss-reflected-json-body/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/xss/xss-reflected-json-body.js
// What: Tier 2 reflected-XSS plugin for JSON request bodies.
// Why: The query-point reflection plugin replays a body point through the
//   urlencoded form builder, so a JSON API never parses the payload and the
//   reflection is missed. Rebuilding the object around the discovered field
//   and sending it as application/json needs a script. The evidence ladder
//   stays engine-owned: a parser-recognized execution payload plus a clean
//   control reaches static-execution-evidence, never a browser claim.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const jsonContentType = "application/json";
  const contexts = ["html", "attr", "attr-executable", "script", "url", "url-executable"];
  const maxSends = 60;
  let sends = 0;

  for (const point of points) {
    const loc = String(point.paramLocation || "query").toLowerCase();
    if (loc !== "body") {
      continue;
    }
    if (!point.paramName) {
      continue;
    }
    if (sends + 1 > maxSends) {
      break;
    }
    const name = point.paramName;
    const canary = probe.canary();
    // Tags and quote characters are JSON-string safe, so the object stays
    // parseable while the value is still an executing pattern in HTML.
    const payload = "<img src=x onerror=alert(" + canary + ")>";
    sends++;
    const resp = probe.send({
      url: point.url,
      method: point.method,
      paramName: "",
      paramLocation: "body",
      value: '{"' + name + '":"' + payload + '"}',
      headers: { "Content-Type": jsonContentType },
    });
    const ev = host.oracles.reflection(resp, canary, contexts);
    if (ev) {
      candidates.push(host.candidate(point, "reflected-xss", ev));
    }
  }
  return candidates;
}
