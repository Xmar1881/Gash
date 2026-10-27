/* ---
id: xss-path-segment
name: Reflected XSS via Path Segment
description: Detects reflected XSS when the payload lands in the URL path rather than a query parameter or body field, appending an encoded executable payload as a path segment and grading it with the reflection oracle against the unmodified base page.
author: GASH contributors
severity: high
tags: [xss, client, reflection, url-sink, path]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 116
api_version: "1.0"
tests: tests/fixtures/xss-path-segment/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/xss/xss-path-segment.js
// What: Tier 2 reflected-XSS plugin for path-borne injection.
// Why: The engine's injection surface carries query, body, cookie and fragment
//   points; a routing framework that echoes the path (error pages, profile
//   slugs, file browsers) is never tested. Only a script can synthesize a path
//   segment outside the point model. The control is the unmodified base page:
//   the reflection binding re-fetches the URL supplied in the response object,
//   so the canary can only survive there if the page genuinely reflects it.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const maxSends = 40;
  const contexts = ["html", "attr-executable", "script", "url", "url-executable"];
  let sends = 0;
  const seen = {};

  for (const point of points) {
    const base = String(point.url || "").split("?")[0].split("#")[0].replace(/\/+$/, "");
    if (!base || seen[base]) {
      continue; // one path probe per base URL
    }
    seen[base] = true;
    if (sends + 2 > maxSends) {
      break;
    }
    const canary = probe.canary();
    // Encoded so the segment is a legal URL; a framework that decodes path
    // parameters reflects the raw tag, while a framework that does not leaves
    // the canary encoded and the pre-gate below stops the attempt.
    const payload = '%22%3E%3Csvg%20onload%3Dalert(' + canary + ')%3E';
    const attackURL = base + "/" + payload + ".html";
    sends++;
    const resp = probe.send({
      url: attackURL,
      method: "GET",
      paramName: "",
      paramLocation: "query",
      value: "",
    });
    if (!resp || !resp.body || String(resp.body).indexOf(canary) === -1) {
      continue; // the path never reaches the response: nothing to grade
    }
    // The binding performs the control GET against this URL; the base page
    // never carried our payload, so a canary surviving there blocks the claim.
    const ev = host.oracles.reflection(
      { status: resp.status, headers: resp.headers || {}, body: resp.body, url: base },
      canary,
      contexts
    );
    if (ev) {
      candidates.push(host.candidate(
        { url: attackURL, method: "GET", paramName: "", paramLocation: "path", value: payload },
        "reflected-xss",
        ev
      ));
    }
  }
  return candidates;
}
