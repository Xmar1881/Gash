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

  // Group points by render base and walk bases round-robin, so every base
  // gets a store+render attempt before any base gets a second one, and the
  // whole run stays inside a send budget. The old flat loop spent two
  // requests per discovered point with no bound and blew the plugin time
  // budget on large surfaces (measured: 79 points -> timeout -> stored XSS
  // missed entirely).
  const bases = [];
  const byBase = [];
  for (const p of points) {
    const base = String(p.url || "").split("?")[0].split("#")[0];
    if (!base) {
      continue;
    }
    let bi = bases.indexOf(base);
    if (bi === -1) {
      bases.push(base);
      byBase.push([]);
      bi = bases.length - 1;
    }
    byBase[bi].push(p);
  }

  const maxSends = 60;
  let sends = 0;
  const done = [];
  let maxDepth = 0;
  for (let i = 0; i < byBase.length; i++) {
    done.push(false);
    if (byBase[i].length > maxDepth) {
      maxDepth = byBase[i].length;
    }
  }

  for (let round = 0; round < maxDepth; round++) {
    let alive = false;
    for (let bi = 0; bi < bases.length; bi++) {
      if (done[bi] || round >= byBase[bi].length) {
        continue;
      }
      alive = true;
      if (sends + 2 > maxSends) {
        return candidates;
      }
      const point = byBase[bi][round];
      const canary = probe.canary();
      const payload = "<img src=x onerror=alert(" + canary + ")>";
      let storeResp, renderResp;
      try {
        sends++;
        storeResp = probe.send(point.withValue(payload));
        sends++;
        renderResp = probe.send({url: bases[bi], method: "GET", paramName: "", paramLocation: "query", value: ""});
      } catch (e) {
        continue;
      }
      // Sibling render pages never received the payload: they are the clean
      // control for the stored oracle (and the opt-in browser-verify pass).
      let controlUrl = "";
      for (const b of bases) {
        if (b !== bases[bi]) {
          controlUrl = b;
          break;
        }
      }
      const contexts = ["html", "attr-executable", "script", "url", "url-executable"];
      const ev = controlUrl
        ? host.oracles.storedExecution(storeResp, renderResp, canary, {contexts: contexts, controlUrl: controlUrl})
        : host.oracles.storedExecution(storeResp, renderResp, canary, contexts);
      if (ev) {
        candidates.push(host.candidate(point, "stored", ev));
        done[bi] = true;
      }
    }
    if (!alive) {
      return candidates;
    }
  }
  return candidates;
}
