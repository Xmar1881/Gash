/* ---
id: web-cache-method-override
name: Web Cache Poisoning via Unkeyed Method-Override Header (differential)
description: Detects web cache poisoning by priming a URL with an unkeyed method-override header carrying a canary and then re-fetching it with no headers, confirming the canary survives in the cached response.
author: GASH contributors
severity: high
tags: [cache-poisoning, web-cache, differential, headers]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 67
api_version: "1.0"
tests: tests/fixtures/web-cache-method-override/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/cache-poisoning/web-cache-method-override.js
// What: Tier 2 cache-poisoning plugin for the unkeyed method-override family.
// Why: Tier 1 host-header checks send one probe and read one response; cache
//   poisoning is a three-beat sequence (clean read, prime, clean read) and the
//   only proof is that the canary OUTLIVES the priming request. The forwarded
//   -host family is covered separately; proxies that honour X-HTTP-Method-
//   Override without keying the cache are a distinct unkeyed surface. The
//   plugin pre-gates on the canary being absent before and present after, then
//   lets the differential oracle enforce 3/3 stability. Only GET leaves the
//   scanner, so no destructive method is ever dispatched.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  // Method-override family: proxies commonly honour these without keying the cache.
  const headerNames = ["X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"];
  const maxSends = 60;
  const sendsPerPoint = 8; // 3 clean + 1 prime + 3 clean + 1 control
  let sends = 0;
  const seen = {};

  for (const point of points) {
    const base = String(point.url || "").split("#")[0];
    if (!base || seen[base]) {
      continue; // one poisoning sequence per URL
    }
    seen[base] = true;
    if (sends + sendsPerPoint > maxSends) {
      break;
    }
    const clean = () => ({
      url: base,
      method: "GET",
      paramName: "",
      paramLocation: "query",
      value: "",
    });

    // Beat 1: clean reads BEFORE priming. They are the false branch and the
    // baseline: any canary here means the URL is already poisoned by someone
    // else and this sequence proves nothing.
    const cleanBefore = [];
    for (let i = 0; i < 3; i++) {
      sends++;
      cleanBefore.push(probe.send(clean()));
    }

    // Beat 2: prime with the unkeyed method-override header set to a canary.
    const canaryMethod = probe.canary();
    const primeHeaders = {};
    for (const name of headerNames) {
      primeHeaders[name] = canaryMethod;
    }
    sends++;
    probe.send({
      url: base,
      method: "GET",
      paramName: "",
      paramLocation: "query",
      value: "",
      headers: primeHeaders,
    });

    // Beat 3: clean reads AFTER priming. The canary can only appear here if
    // the response was cached and served without the priming header.
    const cleanAfter = [];
    for (let i = 0; i < 3; i++) {
      sends++;
      cleanAfter.push(probe.send(clean()));
    }

    const carries = (r) => r && r.body && r.body.indexOf(canaryMethod) !== -1;
    let poisoned = true;
    for (const r of cleanAfter) {
      if (!carries(r)) {
        poisoned = false;
        break;
      }
    }
    if (poisoned) {
      for (const r of cleanBefore) {
        if (carries(r)) {
          poisoned = false;
          break;
        }
      }
    }
    if (!poisoned) {
      continue;
    }

    sends++;
    const controlResp = probe.send({
      url: base,
      method: "GET",
      paramName: "",
      paramLocation: "query",
      value: "",
      headers: { "X-HTTP-Method-Override": "gash-control-neutral" },
    });
    const ev = host.oracles.differential(cleanAfter, cleanBefore, controlResp);
    if (ev) {
      candidates.push(host.candidate(point, "differential", ev));
    }
  }
  return candidates;
}
