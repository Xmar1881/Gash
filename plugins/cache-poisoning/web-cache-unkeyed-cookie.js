/* ---
id: web-cache-unkeyed-cookie
name: Web Cache Poisoning via Unkeyed Cookie (Differential)
description: Detects web cache poisoning by priming a URL with an unkeyed canary cookie and then re-fetching it with no cookies, confirming only when the canary survives in the cached response and was absent before priming.
author: GASH contributors
severity: high
tags: [cache-poisoning, web-cache, differential, cookies]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 71
api_version: "1.0"
tests: tests/fixtures/web-cache-unkeyed-cookie/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/cache-poisoning/web-cache-unkeyed-cookie.js
// What: Tier 2 cache-poisoning plugin for unkeyed cookies.
// Why: The unkeyed-header plugin covers the forwarded-host and method-override
//   families; a cache that ignores the Cookie header entirely is a different
//   surface, and it is the one that turns a per-user value into a shared one.
//   The proof is a three-beat sequence (clean read, prime, clean read) where
//   the canary must OUTLIVE the priming request and must have been absent
//   before it. Correlated reads plus a per-point Cookie header are what a
//   single-request Tier 1 file cannot express.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const cookieName = "gash_cache_track";
  const maxSends = 60;
  let sends = 0;
  const seen = {};

  for (const point of points) {
    const base = String(point.url || "").split("#")[0];
    if (!base || seen[base]) {
      continue; // one poisoning sequence per URL
    }
    seen[base] = true;
    if (sends + 8 > maxSends) {
      break;
    }
    const clean = () => ({
      url: base,
      method: "GET",
      paramName: "",
      paramLocation: "query",
      value: "",
    });

    // Beat 1: clean reads BEFORE priming (false branch and baseline). A canary
    // here means the URL was already poisoned and this sequence proves nothing.
    const cleanBefore = [];
    for (let i = 0; i < 3; i++) {
      sends++;
      cleanBefore.push(probe.send(clean()));
    }

    // Beat 2: prime with the unkeyed cookie set to a per-run canary.
    const canary = probe.canary();
    sends++;
    probe.send({
      url: base,
      method: "GET",
      paramName: "",
      paramLocation: "query",
      value: "",
      headers: { Cookie: cookieName + "=" + canary },
    });

    // Beat 3: clean reads AFTER priming; the canary can only appear here when
    // the response was cached and served without the priming cookie.
    const cleanAfter = [];
    for (let i = 0; i < 3; i++) {
      sends++;
      cleanAfter.push(probe.send(clean()));
    }

    let poisoned = true;
    for (let i = 0; i < cleanAfter.length; i++) {
      if (!carries(cleanAfter[i], canary)) {
        poisoned = false;
        break;
      }
    }
    if (poisoned) {
      for (let i = 0; i < cleanBefore.length; i++) {
        if (carries(cleanBefore[i], canary)) {
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
      headers: { Cookie: cookieName + "=gash-control-neutral" },
    });
    const ev = host.oracles.differential(cleanAfter, cleanBefore, controlResp);
    if (ev) {
      candidates.push(host.candidate(point, "differential", ev));
    }
  }
  return candidates;
}

// carries reports whether a response body contains the canary verbatim.
function carries(resp, canary) {
  return Boolean(resp) && Boolean(resp.body) && String(resp.body).indexOf(canary) !== -1;
}
