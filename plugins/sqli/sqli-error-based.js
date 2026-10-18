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
// internal/fuzz/sqli_corpus.go (locked by a sync test): boolean pair first
// for differential targets, then ten DBMS error probes with case-mixing,
// double-encoding, tab and MySQL versioned-comment variants. Every probe is
// read-only and non-destructive.

const SQLI_PROBES = [
  "' AND '1'='1",
  "' AND '1'='2",
  "AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))",
  "AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)",
  "AND 1=CONVERT(int,@@version)",
  "AND 1=CAST(VERSION() AS int)",
  "AND 1=CAST(sqlite_version() AS int)",
  "aNd 1=CoNvErT(iNt,@@version)",
  "%27%20AND%201=1--%20",
  "%2527%2520AND%25201=1--%2520",
  "'%09AND%09/**/1=1--",
  "/*!50000AND*/ 1=1--"
];

function run(probe, ctx) {
  const points = ctx.injectionPoints();

  const candidates = [];
  const maxSends = 60; // request budget per run; corpus stays well under it
  let sends = 0;
  for (const point of points) {
    if (sends + 1 + SQLI_PROBES.length > maxSends) {
      return candidates;
    }
    sends++;
    const controlResp = probe.send(point.withValue("gash-control"));
    for (const payload of SQLI_PROBES) {
      sends++;
      const resp = probe.send(point.withValue(payload));
      const ev = host.oracles.error(resp, controlResp);
      if (ev) {
        candidates.push(host.candidate(point.withValue(payload), "sqli-error", ev));
        break;
      }
    }
  }
  return candidates;
}
