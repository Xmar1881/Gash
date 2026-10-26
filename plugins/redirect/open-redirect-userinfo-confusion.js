/* ---
id: open-redirect-userinfo-confusion
name: Open Redirect via URL Parser Confusion
description: Detects open redirects that survive naive allowlist checks by sending protocol-relative, userinfo, suffix and fragment confusion variants per point and grading the Location header with the redirect oracle against a control.
author: GASH contributors
severity: medium
tags: [open-redirect, redirect, misconfig, client]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 51
api_version: "1.0"
tests: tests/fixtures/open-redirect-userinfo-confusion/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/redirect/open-redirect-userinfo-confusion.js
// What: Tier 2 redirect plugin for URL-parser confusion variants.
// Why: The Tier 1 plugin sends one payload shape per file. Real allowlists
//   often check "does the value CONTAIN our host" or "does it END WITH our
//   host": those checks pass for `https://trusted@evil`, `//evil` and
//   `https://trusted.evil`, which a single-payload file cannot all reach. The
//   payload host is a per-run canary, so the oracle grades a Location that can
//   only come from our own payload. No new sandbox surface.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const maxSends = 40;
  let sends = 0;
  const seen = {};

  for (const point of points) {
    const loc = String(point.paramLocation || "query").toLowerCase();
    if (loc !== "query" && loc !== "body") {
      continue;
    }
    if (!point.paramName) {
      continue;
    }
    const base = String(point.url || "").split("#")[0];
    const m = /^https?:\/\/([^\/?#]+)/i.exec(base);
    if (!m) {
      continue;
    }
    // The trusted host is the target's own host (userinfo stripped), which is
    // what a naive `contains(host)` allowlist would look for.
    const trusted = m[1].split("@").pop();
    const key = base + "|" + point.paramName;
    if (seen[key]) {
      continue;
    }
    seen[key] = true;
    if (sends + 4 > maxSends) {
      break;
    }
    const evil = probe.canary() + ".gash-redirect.example";
    const variants = [
      "//" + evil + "/",                        // protocol-relative: host takeover
      "https://" + trusted + "@" + evil + "/",  // userinfo confusion
      "https://" + trusted + "." + evil + "/",  // suffix confusion
      "https://" + evil + "#" + trusted,        // fragment confusion
    ];
    for (const payload of variants) {
      if (sends >= maxSends) {
        break;
      }
      sends++;
      const resp = probe.send(point.withValue(payload));
      // The oracle compares the Location host against the exact payload host,
      // so a hop that stays on the target can never be graded as external.
      const ev = host.oracles.redirect(resp, evil);
      if (ev) {
        candidates.push(host.candidate(point.withValue(payload), "open-redirect", ev));
        break;
      }
    }
  }
  return candidates;
}
