/* ---
id: xpath-xml-body-error
name: XPath Injection in XML Body (error-based)
description: Detects XPath injection when a discovered field is placed into an XML request element and closure payloads provoke parser or compiler errors that are absent for the neutral-value control.
author: GASH contributors
severity: medium
tags: [xpath, injection, xml]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 112
api_version: "1.0"
tests: tests/fixtures/xpath-xml-body-error/
oracle_params:
  mode: xpath
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/xpath/xpath-xml-body-error.js
// What: Tier 2 error-based XPath plugin for XML request bodies.
// Why: XPath injection is an XML-native class, yet the existing XPath checks
//   approximate it through query parameters and JSON fields. A real XML
//   endpoint receives the payload as element text; only a script can rebuild
//   that document per discovered field and send an explicit application/xml
//   content type. The error oracle's xpath mode sets the firm ceiling.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const xmlContentType = "application/xml";
  // Harmless string closures: they unbalance the expression without reading
  // documents, enumerating nodes, or causing entity expansion.
  const payloads = ["' or '1'='1", "'] | //* | //*['", "' or 1=1 or '"];
  const maxSends = 40;
  let sends = 0;

  const tagFor = (name) => {
    const clean = String(name || "").replace(/[^A-Za-z0-9_.-]/g, "_");
    return clean || "value";
  };
  const documentFor = (tag, value) =>
    '<?xml version="1.0" encoding="UTF-8"?><request><' + tag + '>' + value + '</' + tag + '></request>';

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
    const tag = tagFor(point.paramName);
    const raw = (value) => ({
      url: point.url,
      method: point.method,
      paramName: "",
      paramLocation: "body",
      value: documentFor(tag, value),
      headers: { "Content-Type": xmlContentType },
    });
    let found = false;
    for (const payload of payloads) {
      if (found) {
        break;
      }
      sends++;
      const resp = probe.send(raw(payload));
      sends++;
      const controlResp = probe.send(raw("1"));
      const ev = host.oracles.error(resp, controlResp);
      if (ev) {
        candidates.push(host.candidate(point, "error", ev));
        found = true;
      }
    }
  }
  return candidates;
}
