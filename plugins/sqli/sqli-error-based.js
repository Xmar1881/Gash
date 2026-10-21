/* ---
id: sqli-error-based
name: SQLi Error Based
description: Detects error-based SQL injection via database signature match plus absent-in-control proof.
author: GASH contributors
severity: high
tags: [sqli, injection]
safe: true
deep: false
active: false
requires_auth: false
phase: probe
order: 50
api_version: "1.0"
tests: tests/fixtures/sqli-error-based/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/sqli/sqli-error-based.js
// What: Tier 2 error-based SQLi plugin backed by ErrorSignatureOracle.
// Why: Reference for signature-plus-control evidence; a signature that also
//   appears in the control response must reject instead of confirming.
//
// The probe corpus below is the literal mirror of fuzz.SQLiProbes() in
// internal/fuzz/sqli_corpus.go (locked by a sync test). Execution starts with
// SQLI_PRIORITY: prefix-preserving quote/paren breaks first, then the
// differential boolean pair, then the remaining DBMS error probes. Every
// probe is read-only and non-destructive.

const SQLI_PROBES = [
  "' AND '1'='1",
  "' AND '1'='2",
  "1'",
  "1\"",
  "1)",
  "AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))",
  "AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)",
  "AND 1=CONVERT(int,@@version)",
  "AND 1=CAST(VERSION() AS int)",
  "AND 1=CAST(sqlite_version() AS int)",
  "aNd 1=CoNvErT(iNt,@@version)",
  "%27%20AND%201=1--%20",
  "%2527%2520AND%25201=1--%2520",
  "'%09AND%09/**/1=1--",
  "/*!50000AND*/ 1=1--",
  "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--"
];

const SQLI_PRIORITY = [
  "1'",
  "1\"",
  "1)",
  "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
];

function run(probe, ctx) {
  const HOT_PARAMS = /^(id|name|q|query|search|page|file|path|url|redirect|ip|cmd|user|username|password|txtname|mtxmessage|cat|item|input)$/;
  const rank = (p) => {
    const loc = String(p.paramLocation || "");
    const hasQuery = String(p.url || "").includes("?");
    const hasValue = String(p.value || "") !== "";
    const hasForm = p.formValues && Object.keys(p.formValues).length > 0;
    const hot = HOT_PARAMS.test(String(p.paramName || "").toLowerCase());
    // Real form fields beat incidental link parameters: the per-plugin
    // budget is small and link params (help/source popups) otherwise starve
    // the vulnerable form before its first probe.
    if (hasForm && (loc === "query" || loc === "body")) {
      return hot ? 0 : 1;
    }
    if (loc === "query" && hasQuery && hasValue) {
      return 2;
    }
    if (hasValue) {
      return 3;
    }
    if (loc === "query" || loc === "body") {
      return 4;
    }
    return 5;
  };
  const points = ctx.injectionPoints().filter((p) => {
    const name = String(p.paramName || "").toLowerCase();
    if (/^(submit|button|login|signin|reset|search-submit)$/.test(name)) {
      return false;
    }
    const path = String(p.url || "").toLowerCase().split("?")[0];
    return !/\.(css|js|mjs|map|png|jpe?g|gif|ico|svg|woff2?|ttf|eot|webp)$/.test(path);
  }).sort((a, b) => rank(a) - rank(b));

  const order = SQLI_PRIORITY.concat(
    SQLI_PROBES.filter((p) => SQLI_PRIORITY.indexOf(p) < 0)
  );

  const candidates = [];
  const maxSends = 60; // request budget per run; corpus stays well under it
  let sends = 0;

  // Fair budget: walk the probe corpus round-robin across points and fetch
  // each point's control response lazily before its first probe. A quiet
  // prefix can no longer exhaust the budget and starve later points, and a
  // large surface cannot spend the whole budget on controls alone (measured
  // recall gap: 79 discovered points, /sqli/error sat at index 9 and was
  // never probed).
  const controls = [];
  const done = [];
  for (let i = 0; i < points.length; i++) {
    controls.push(undefined);
    done.push(false);
  }
  for (let pi = 0; pi < order.length; pi++) {
    let alive = false;
    for (let i = 0; i < points.length; i++) {
      if (done[i]) {
        continue;
      }
      if (controls[i] === undefined) {
        if (sends >= maxSends) {
          return candidates;
        }
        sends++;
        controls[i] = probe.send(points[i].withValue("gash-control"));
      }
      if (sends >= maxSends) {
        return candidates;
      }
      sends++;
      const resp = probe.send(points[i].withValue(order[pi]));
      const ev = host.oracles.error(resp, controls[i]);
      if (ev) {
        candidates.push(host.candidate(points[i].withValue(order[pi]), "sqli-error", ev));
        done[i] = true;
      } else {
        alive = true;
      }
    }
    if (!alive) {
      return candidates;
    }
  }
  return candidates;
}
