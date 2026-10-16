/* ---
id: xss-stored-two-step
name: Stored XSS Two-Step (Store plus Render)
description: Detects stored XSS via a two-request flow that stores a payload through a form point and verifies the render page with the stored oracle.
author: GASH contributors
severity: high
tags: [xss, stored-xss, injection, reflection]
safe: false
deep: false
active: true
requires_auth: false
phase: probe
order: 44
api_version: "1.0"
tests: tests/fixtures/xss-stored-two-step/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/xss/xss-stored-two-step.js
// What: Tier 2 stored-XSS plugin with a real store-plus-render flow.
// Why: Tier 1 xss-stored-basic evaluates the synchronous render body offline
//   (approximation). This plugin performs request 1 (store through the surface
//   form point) plus request 2 (render page GET) and verifies the pair with
//   the stored oracle (two-exchange write/render plus clean control).
//   Only probe.send plus surface plus host.oracles.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  for (const point of points) {
    const canary = probe.canary();
    const payload = "<img src=x onerror=alert(" + canary + ")>";
    let storeResp;
    try {
      storeResp = probe.send(point.withValue(payload));
    } catch (e) {
      continue;
    }
    const base = String(point.url).split("?")[0].split("#")[0];
    const renderPoint = {url: base, method: "GET", paramName: "", paramLocation: "query", value: ""};
    let renderResp;
    try {
      renderResp = probe.send(renderPoint);
    } catch (e) {
      continue;
    }
    const ev = host.oracles.storedExecution(storeResp, renderResp, canary, ["html", "attr-executable", "script", "url", "url-executable"]);
    if (ev) {
      candidates.push(host.candidate(point, "stored", ev));
    }
  }
  return candidates;
}
