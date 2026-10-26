/* ---
id: file-upload-served
name: File Upload Validation Bypass (serve-back proof)
description: Detects upload validation bypass by uploading a mismatched-type artifact with an executable canary payload, locating the URL the server hands out, and verifying the artifact is served back with an active content type.
author: GASH contributors
severity: high
tags: [file-upload, unrestricted, validation-bypass, stored-xss, json]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 75
api_version: "1.0"
tests: tests/fixtures/file-upload-served/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/file-upload/file-upload-served.js
// What: Tier 2 upload validation-bypass plugin with a serve-back proof.
// Why: An accepted upload proves nothing on its own — the impact depends on
//   how the artifact comes back. The reflection oracle reasons about the HTML
//   context of a page, not about the content type an uploaded file is served
//   with, so the engine owns a dedicated upload-served oracle: active content
//   type means confirmed, inert or unknown means firm, and a missing artifact
//   or a dirty control means reject. When the URL cannot be located in the
//   upload response the plugin claims nothing (false negative, never noise).

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const boundary = "----gashUploadBoundary9c1f2b";
  const multipartType = "multipart/form-data; boundary=" + boundary;
  const maxSends = 40;
  let sends = 0;

  const filePart = (name, filename, declaredType, content) =>
    "--" + boundary + "\r\n" +
    'Content-Disposition: form-data; name="' + name + '"; filename="' + filename + '"\r\n' +
    "Content-Type: " + declaredType + "\r\n\r\n" +
    content + "\r\n";
  const closeBody = (parts) => parts.join("") + "--" + boundary + "--\r\n";

  // locateURL finds the URL the server handed out for our artifact. The
  // filename carries the per-run canary, so a match is unambiguous; without a
  // locatable URL no claim is made.
  const locateURL = (body, filename, base) => {
    const text = String(body || "");
    const idx = text.indexOf(filename);
    if (idx === -1) {
      return "";
    }
    let start = idx;
    while (start > 0) {
      const ch = text.charAt(start - 1);
      if (ch === '"' || ch === "'" || ch === " " || ch === ">" || ch === "<" ||
          ch === "\n" || ch === "\r" || ch === "(" || ch === "=" || ch === "," ||
          ch === ":" || ch === ";") {
        break;
      }
      start--;
    }
    let url = text.slice(start, idx + filename.length);
    if (url.indexOf("/") === -1) {
      return "";
    }
    if (!/^https?:\/\//i.test(url)) {
      const m = /^(https?:\/\/[^\/]+)/i.exec(String(base || ""));
      if (!m) {
        return "";
      }
      url = m[1] + (url.charAt(0) === "/" ? "" : "/") + url;
    }
    return url;
  };

  for (const point of points) {
    const loc = String(point.paramLocation || "query").toLowerCase();
    if (loc !== "body") {
      continue; // uploads are body exchanges
    }
    if (!point.paramName) {
      continue;
    }
    if (String(point.method || "").toUpperCase() !== "POST") {
      continue; // a file upload is a POST
    }
    if (sends + 3 > maxSends) {
      break;
    }
    const canary = probe.canary();
    const filename = canary + ".html";
    // The declared part type deliberately mismatches the extension, which is
    // the validation gap under test.
    const payload = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(' + canary + ')"></svg>';
    const body = closeBody([filePart(point.paramName, filename, "image/png", payload)]);

    sends++;
    const uploadResp = probe.send({
      url: point.url,
      method: point.method,
      paramName: "",
      paramLocation: "body",
      value: body,
      headers: { "Content-Type": multipartType },
    });
    const artifactURL = locateURL(uploadResp && uploadResp.body, filename, point.url);
    if (!artifactURL) {
      continue;
    }
    sends++;
    const fetchResp = probe.send({
      url: artifactURL,
      method: "GET",
      paramName: "",
      paramLocation: "query",
      value: "",
    });
    // A sibling name that was never uploaded: the control proves the served
    // artifact is ours and not a pre-existing file (binding performs the GET).
    const controlURL = artifactURL.split(filename).join(canary + "_never.html");
    sends++;
    const ev = host.oracles.uploadServed(uploadResp, fetchResp, canary, {
      controlUrl: controlURL,
    });
    if (ev) {
      candidates.push(host.candidate(point, "upload-served", ev));
    }
  }
  return candidates;
}
