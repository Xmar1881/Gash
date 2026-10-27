/* ---
id: sqli-multipart-error
name: SQL Injection in Multipart Form (error-based)
description: Detects SQL injection in multipart/form-data fields by replaying the complete form with a closure payload in the discovered field and requiring a database error signature absent from the neutral-value control.
author: GASH contributors
severity: high
tags: [sqli, injection, multipart, forms]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 113
api_version: "1.0"
tests: tests/fixtures/sqli-multipart-error/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/sqli/sqli-multipart-error.js
// What: Tier 2 error-based SQLi plugin for multipart/form-data bodies.
// Why: Tier 1 injects through the urlencoded form builder, which cannot emit a
//   multipart part or replay the sibling fields of a multipart form. The body,
//   the boundary and the matching content type must be built by the script;
//   sibling fields (CSRF tokens included) are replayed so the server reaches
//   its handler instead of answering a validation error.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const boundary = "----gashSqliMultipart5d2c";
  const multipartType = "multipart/form-data; boundary=" + boundary;
  const payloads = ["'", "1'", "' OR '1'='1"];
  const maxSends = 40;
  let sends = 0;

  const part = (name, value) =>
    "--" + boundary + "\r\n" +
    'Content-Disposition: form-data; name="' + name + '"\r\n\r\n' +
    value + "\r\n";
  const bodyFor = (point, value) => {
    let out = "";
    const values = point.formValues || {};
    for (const name in values) {
      if (name === point.paramName) {
        continue;
      }
      out += part(name, String(values[name]));
    }
    out += part(point.paramName, value);
    return out + "--" + boundary + "--\r\n";
  };

  for (const point of points) {
    if (String(point.paramLocation || "").toLowerCase() !== "body") {
      continue;
    }
    if (!point.paramName) {
      continue;
    }
    if (String(point.method || "").toUpperCase() !== "POST") {
      continue; // multipart submissions are POST exchanges
    }
    if (String(point.formEnctype || "").toLowerCase().indexOf("multipart/form-data") === -1) {
      continue; // only forms that actually declared multipart
    }
    if (sends + payloads.length * 2 > maxSends) {
      break;
    }
    const raw = (value) => ({
      url: point.url,
      method: point.method,
      paramName: "",
      paramLocation: "body",
      value: bodyFor(point, value),
      headers: { "Content-Type": multipartType },
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
        candidates.push(host.candidate(point, "sqli-error", ev));
        found = true;
      }
    }
  }
  return candidates;
}
