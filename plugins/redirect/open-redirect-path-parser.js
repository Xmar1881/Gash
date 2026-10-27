/* ---
id: open-redirect-path-parser
name: Open Redirect via Path Parser Confusion
description: Detects open redirects that survive naive path allowlists by sending protocol-relative, backslash and encoded-slash path variants and grading the Location header with the redirect oracle against a neutral-path control.
author: GASH contributors
severity: medium
tags: [open-redirect, redirect, misconfig, path]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 118
api_version: "1.0"
tests: tests/fixtures/open-redirect-path-parser/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/redirect/open-redirect-path-parser.js
// What: Tier 2 redirect plugin for path parser-confusion variants.
// Why: The query-parameter redirect plugins assume the value arrives as a
//   parameter. Routers that normalize a path and hand it to the login redirect
//   see `//host`, `/\host` and encoded-slash forms differently; only a script
//   can synthesize those path shapes and pair each with a neutral-path control.
//   The payload host is a per-run canary, so the oracle grades a Location that
//   can only come from our own payload.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const maxSends = 40;
  let sends = 0;
  const seen = {};

  const locationOf = (headers) => {
    if (!headers) {
      return "";
    }
    for (const name in headers) {
      if (String(name).toLowerCase() === "location") {
        return String(headers[name] || "");
      }
    }
    return "";
  };

  for (const point of points) {
    const base = String(point.url || "").split("?")[0].split("#")[0].replace(/\/+$/, "");
    if (!base || seen[base]) {
      continue; // one parser matrix per base URL
    }
    seen[base] = true;
    if (sends + 2 > maxSends) {
      break;
    }
    // Canaries carry an underscore; DNS labels do not, so normalize it.
    const canary = probe.canary().replace(/_/g, "-");
    const payloadHost = "gash-" + canary + ".example";
    const variants = [
      "//" + payloadHost + "/",         // protocol-relative path
      "/\\" + payloadHost + "/",        // backslash normalization
      "/%5c" + payloadHost + "/",       // encoded backslash
      "/%2f%2f" + payloadHost + "/",    // encoded slashes
    ];
    let found = false;
    for (const variant of variants) {
      if (found || sends + 2 > maxSends) {
        break;
      }
      const attackURL = base + variant;
      sends++;
      const resp = probe.send({
        url: attackURL,
        method: "GET",
        paramName: "",
        paramLocation: "query",
        value: "",
      });
      sends++;
      // The redirect binding assumes a clean control; this neutral path proves
      // it, so a pre-existing external rewrite cannot be attributed to us.
      const ctrl = probe.send({
        url: base + "/gash-neutral-path",
        method: "GET",
        paramName: "",
        paramLocation: "query",
        value: "",
      });
      if (ctrl && locationOf(ctrl.headers).indexOf(payloadHost) !== -1) {
        continue;
      }
      const ev = host.oracles.redirect(resp, payloadHost);
      if (ev) {
        candidates.push(host.candidate(
          { url: attackURL, method: "GET", paramName: "", paramLocation: "path", value: variant },
          "open-redirect",
          ev
        ));
        found = true;
      }
    }
  }
  return candidates;
}
