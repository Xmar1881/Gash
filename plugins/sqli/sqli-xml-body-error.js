/* ---
id: sqli-xml-body-error
name: SQL Injection in XML Body (error-based)
description: Detects SQL injection in XML and SOAP request bodies by injecting a closure payload into the discovered field element, sending an explicit application/xml document, and requiring a database error signature absent from the neutral-value control.
author: GASH contributors
severity: high
tags: [sqli, injection, xml, soap]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 111
api_version: "1.0"
tests: tests/fixtures/sqli-xml-body-error/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/sqli/sqli-xml-body-error.js
// What: Tier 2 error-based SQLi plugin for XML/SOAP request bodies.
// Why: The urlencoded form builder never produces an XML document, and Tier 1
//   declares one static body per file, so a discovered field cannot be placed
//   into a per-run XML envelope. XML and SOAP endpoints feed element text into
//   SQL statements just like JSON APIs do; the payload sits inside the element
//   named after the discovered field and the error oracle still decides.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const xmlContentType = "application/xml";
  const payloads = ["'", "1'", "' OR '1'='1"];
  const maxSends = 40;
  let sends = 0;

  // XML element names cannot carry brackets or spaces; map anything unusual to
  // an underscore so the document stays well formed for every point.
  const tagFor = (name) => {
    const clean = String(name || "").replace(/[^A-Za-z0-9_.-]/g, "_");
    return clean || "value";
  };
  const documentFor = (tag, value) =>
    '<?xml version="1.0" encoding="UTF-8"?><request><' + tag + '>' + value + '</' + tag + '></request>';

  for (const point of points) {
    if (String(point.paramLocation || "").toLowerCase() !== "body") {
      continue; // an XML document only reaches a request body
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
      // The neutral document keeps the same shape, so a parser that rejects
      // XML outright cannot produce a signature that is absent for the control.
      const controlResp = probe.send(raw("1"));
      const ev = host.oracles.error(resp, controlResp);
      if (ev) {
        candidates.push(host.candidate(point, "sqli-error", ev));
        found = true;
      }
    }
  }
  return candidates;
}
