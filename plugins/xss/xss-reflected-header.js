/* ---
id: xss-reflected-header
name: Reflected XSS via Request Header
description: Detects reflected XSS when a request header such as User-Agent or Referer is echoed into an executable HTML context, grading the response with the reflection oracle against a clean header-less control request.
author: GASH contributors
severity: medium
tags: [xss, client, reflection, headers]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 117
api_version: "1.0"
tests: tests/fixtures/xss-reflected-header/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/xss/xss-reflected-header.js
// What: Tier 2 reflected-XSS plugin for header-borne reflection.
// Why: The discovered surface never contains header points, yet error pages,
//   "welcome back" panels and access logs routinely echo User-Agent or Referer
//   into HTML. A header value has to be attached per request, which the point
//   model cannot express; the stored-header plugin covers persistence, not
//   immediate reflection. The reflection binding re-fetches the same URL
//   without the header as the clean control, so an echo alone is not enough.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const maxSends = 40;
  const contexts = ["html", "attr-executable", "script", "url", "url-executable"];
  const headerNames = ["User-Agent", "Referer"];
  let sends = 0;
  const seen = {};

  for (const point of points) {
    const base = String(point.url || "").split("?")[0].split("#")[0];
    if (!base || seen[base]) {
      continue; // one reflection attempt per base URL
    }
    seen[base] = true;
    const canary = probe.canary();
    const payloads = [
      "<svg onload=alert(" + canary + ")>",
      '"><img src=x onerror=alert(' + canary + ")>",
    ];
    let found = false;
    for (const headerName of headerNames) {
      for (const payload of payloads) {
        if (found || sends >= maxSends) {
          break;
        }
        sends++;
        const headers = {};
        headers[headerName] = payload;
        const resp = probe.send({
          url: base,
          method: "GET",
          paramName: "",
          paramLocation: "query",
          value: "",
          headers: headers,
        });
        if (!resp || !resp.body || String(resp.body).indexOf(canary) === -1) {
          continue; // the header never reaches the response
        }
        const ev = host.oracles.reflection(resp, canary, contexts);
        if (ev) {
          candidates.push(host.candidate(
            {
              url: base,
              method: "GET",
              paramName: headerName.toLowerCase(),
              paramLocation: "header",
              value: payload,
            },
            "reflected-xss",
            ev
          ));
          found = true;
          break;
        }
      }
      if (found) {
        break;
      }
    }
  }
  return candidates;
}
