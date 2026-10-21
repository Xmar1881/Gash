/* ---
id: dom-sink-basic
name: DOM Sink (static + browser-confirmed)
description: Detects URL-controlled DOM sinks through the execution oracle; hash routes are exercised in a real browser when available.
author: Gash contributors
severity: medium
tags: [xss, dom, client]
safe: true
deep: false
active: false
requires_auth: false
phase: probe
order: 45
api_version: "1.0"
tests: tests/fixtures/dom-sink-basic/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / Gash contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/xss/dom-sink-basic.js
// What: Tier 2 DOM sink scanner backed by ExecutionOracle.
// Why: Static sink/source analysis caps at firm; fragment queries never reach
//   the server, so those points require a real browser probe.

const DOM_XSS_PAYLOAD = '"><iframe src="javascript:alert(window.__gashCanary=true)"></iframe>';

function routeKey(raw) {
  const s = String(raw || "");
  const hash = s.indexOf("#");
  const base = (hash >= 0 ? s.slice(0, hash) : s).split("?")[0];
  const frag = (hash >= 0 ? s.slice(hash) : "").split("?")[0];
  return base + frag;
}

function evidenceKey(point, location, ev) {
  return [
    routeKey(point.url), point.method, location,
    ev.sink || "", ev.source || "",
  ].join("|");
}

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const seen = new Set();
  for (const point of points) {
    const location = String(point.paramLocation || "").toLowerCase();
    const target = point.withValue(DOM_XSS_PAYLOAD);
    if (location === "fragment") {
      if (!host.oracles.browserExecution) {
        continue;
      }
      const ev = host.oracles.browserExecution(point, DOM_XSS_PAYLOAD);
      if (!ev) {
        continue;
      }
      const key = evidenceKey(point, location, ev);
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      candidates.push(host.candidate(target, "dom-xss", ev));
      continue;
    }
    const resp = probe.send(target);
    let ev = host.oracles.execution(resp);
    if (!ev) {
      continue;
    }
    const key = evidenceKey(point, location, ev);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    if (host.oracles.browserExecution) {
      const confirmed = host.oracles.browserExecution(point, DOM_XSS_PAYLOAD, {
        sink: ev.sink,
        source: ev.source,
      });
      if (confirmed) {
        ev = confirmed;
      }
    }
    candidates.push(host.candidate(target, "dom-xss", ev));
  }
  return candidates;
}
