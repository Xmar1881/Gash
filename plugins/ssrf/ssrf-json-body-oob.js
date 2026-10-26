/* ---
id: ssrf-json-body-oob
name: Blind SSRF via JSON Body Field (OOB)
description: Detects blind SSRF when a JSON API body field is fetched server-side, using a unique out-of-band callback token per discovered field and skipping honestly when no OOB server is configured.
author: GASH contributors
severity: high
tags: [ssrf, json, api, blind, oob]
safe: false
deep: false
active: true
requires_auth: false
phase: probe
order: 70
oob: required
api_version: "1.0"
tests: tests/fixtures/ssrf-json-body-oob/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/ssrf/ssrf-json-body-oob.js
// What: Tier 2 blind-SSRF plugin for JSON request bodies.
// Why: A JSON API field that holds a URL (avatar, webhook, import source) is
//   fetched server-side, but Tier 1 cannot rebuild a JSON object around a
//   discovered field. The callback token is unique per payload, so a hit can
//   only confirm the exact request that caused it; without an OOB server the
//   plugin returns no candidates instead of inventing a tentative finding.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const jsonContentType = "application/json";
  const maxSends = 40;
  const sent = [];

  for (const point of points) {
    if (sent.length >= maxSends) {
      break;
    }
    const loc = String(point.paramLocation || "query").toLowerCase();
    if (loc !== "body") {
      continue;
    }
    if (!point.paramName) {
      continue;
    }
    const oob = host.oob.generate("http");
    if (!oob) {
      // No self-hosted OOB server: the scheduler should have skipped this
      // plugin; returning empty keeps the discipline even if it did not.
      return [];
    }
    const name = point.paramName;
    const body = '{"' + name + '":"' + oob.url + '"}';
    probe.send({
      url: point.url,
      method: point.method,
      paramName: "",
      paramLocation: "body",
      value: body,
      headers: { "Content-Type": jsonContentType },
    });
    sent.push({ corr: oob.correlationId, ns: oob.namespace, point: point, payload: body });
  }
  if (sent.length === 0) {
    return [];
  }

  // ONE shared bounded window for the whole corpus (10s / 2 polls): the token
  // is unique per field, so the matched callback names its exact request.
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
      return [host.candidate(s.point, "ssrf-blind", ev)];
    }
  }
  return [];
}
