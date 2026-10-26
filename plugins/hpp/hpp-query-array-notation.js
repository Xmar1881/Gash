/* ---
id: hpp-query-array-notation
name: HTTP Parameter Pollution via Array Notation
description: Detects array-notation parameter pollution by sending the discovered query parameter as a bracket-array with one and with two elements and comparing the two stable responses against a plain scalar control.
author: GASH contributors
severity: medium
tags: [hpp, parameter-pollution, differential, query]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 73
api_version: "1.0"
tests: tests/fixtures/hpp-query-array-notation/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/hpp/hpp-query-array-notation.js
// What: Tier 2 HPP plugin for bracket-array notation.
// Why: The existing HPP plugins cover duplicate keys (`id=1&id=2`) in query,
//   JSON and multipart bodies. Bracket notation (`id[]=1`) is a different
//   parser path in most frameworks: an array-aware binder turns one element
//   into a slice and two elements into slice[2], which changes the value the
//   business logic sees. Building that raw query per point is not something a
//   single-request Tier 1 file can express.

// stripParam removes the target parameter from a URL query, keeping every
// other parameter untouched so the comparison isolates the polluted one.
function stripParam(rawURL, name) {
  const q = rawURL.indexOf("?");
  if (q === -1) {
    return rawURL;
  }
  const base = rawURL.slice(0, q);
  const rest = rawURL
    .slice(q + 1)
    .split("&")
    .filter((part) => part !== "" && part.split("=")[0] !== name);
  if (rest.length === 0) {
    return base;
  }
  return base + "?" + rest.join("&");
}

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const maxSends = 60;
  let sends = 0;
  const seen = {};

  for (const point of points) {
    if (String(point.paramLocation || "query").toLowerCase() !== "query") {
      continue;
    }
    if (!point.paramName) {
      continue;
    }
    const base = String(point.url || "");
    if (!base) {
      continue;
    }
    const key = base.split("#")[0].split("?")[0] + "|" + point.paramName;
    if (seen[key]) {
      continue;
    }
    seen[key] = true;
    if (sends + 7 > maxSends) {
      break;
    }
    const name = point.paramName;
    const cleaned = stripParam(base, name);
    const sep = cleaned.indexOf("?") === -1 ? "?" : "&";
    const bracket = name + "%5B%5D=";
    const raw = (query) => ({
      url: cleaned + sep + query,
      method: point.method || "GET",
      paramName: "",
      paramLocation: "query",
      value: "",
    });

    // True branch: two array elements. False branch: one. Only an
    // array-aware binder can make those two responses differ.
    const single = bracket + "1";
    const double = bracket + "1&" + bracket + "2";
    const trueResps = [];
    const falseResps = [];
    for (let i = 0; i < 3; i++) {
      sends++;
      trueResps.push(probe.send(raw(double)));
      sends++;
      falseResps.push(probe.send(raw(single)));
    }
    sends++;
    const controlResp = probe.send(raw(name + "=gash-control-neutral"));
    const ev = host.oracles.differential(trueResps, falseResps, controlResp);
    if (ev) {
      candidates.push(host.candidate(point, "differential", ev));
    }
  }
  return candidates;
}
