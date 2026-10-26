/* ---
id: xss-stored-header-two-step
name: Stored XSS via Header-Borne Write (two-step)
description: Detects stored XSS whose write channel is a request header (Referer) rather than a form field, storing a harmless alert payload through the header and verifying the rendered page with the stored oracle plus a sibling control page.
author: GASH contributors
severity: high
tags: [xss, stored-xss, injection, headers]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 48
api_version: "1.0"
tests: tests/fixtures/xss-stored-header-two-step/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/xss/xss-stored-header-two-step.js
// What: Tier 2 stored-XSS plugin for header-borne write channels.
// Why: The existing stored plugins write through a form point or a JSON field.
//   Applications also persist request metadata: a Referer shown on a "came
//   from" panel, a proxy access log rendered in an admin view. That write
//   channel needs no form at all, so the value has to travel as a
//   point-level header and the render has to be re-read afterwards — two
//   correlated exchanges a single-request Tier 1 file cannot express. The
//   render is graded by the stored oracle against a sibling page that never
//   received the payload.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const bases = [];
  const reps = [];
  for (let i = 0; i < points.length; i++) {
    const base = String(points[i].url || "").split("?")[0].split("#")[0];
    if (!base || bases.indexOf(base) !== -1) {
      continue;
    }
    bases.push(base);
    reps.push(points[i]);
  }

  const maxSends = 40;
  let sends = 0;
  const contexts = ["html", "attr-executable", "script", "url", "url-executable"];
  for (let i = 0; i < bases.length; i++) {
    if (sends + 2 > maxSends) {
      break;
    }
    const canary = probe.canary();
    // Harmless payload: one alert carrying the canary, nothing persistent.
    const payload = "<img src=x onerror=alert(" + canary + ")>";
    sends++;
    const storeResp = probe.send({
      url: bases[i],
      method: "GET",
      paramName: "",
      paramLocation: "query",
      value: "",
      headers: { Referer: payload },
    });
    sends++;
    const renderResp = probe.send({
      url: bases[i],
      method: "GET",
      paramName: "",
      paramLocation: "query",
      value: "",
    });
    // A sibling page that never saw the payload is the clean control; without
    // one the stored claim would be unprovable.
    let controlUrl = "";
    for (let j = 0; j < bases.length; j++) {
      if (j !== i) {
        controlUrl = bases[j];
        break;
      }
    }
    if (!controlUrl) {
      continue;
    }
    const ev = host.oracles.storedExecution(storeResp, renderResp, canary, {
      contexts: contexts,
      controlUrl: controlUrl,
    });
    if (ev) {
      candidates.push(host.candidate(reps[i], "stored", ev));
    }
  }
  return candidates;
}
