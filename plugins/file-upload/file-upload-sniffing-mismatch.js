/* ---
id: file-upload-sniffing-mismatch
name: File Upload Content Sniffing (serve-back proof)
description: Detects servers that sniff an uploaded artifact instead of honouring the inert declared type, uploading a text-named octet-stream part with active content and verifying the served content type on the fetch-back plus a sibling control.
author: GASH contributors
severity: medium
tags: [file-upload, misconfig, sniffing, stored-xss, serve-back]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 78
api_version: "1.0"
tests: tests/fixtures/file-upload-sniffing-mismatch/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/file-upload/file-upload-sniffing-mismatch.js
// What: Tier 2 content-sniffing upload plugin with a serve-back proof.
// Why: The serve-back plugin asks whether a mismatched extension is accepted.
//   This one asks a different question: the declaration and the extension are
//   BOTH inert (`octet-stream` / `.txt`) — does the server ignore them and
//   serve the artifact according to its content? Only the served content type
//   answers it, which is exactly what the upload-served oracle grades; a
//   sibling name that was never uploaded is the control, and an unlocatable
//   artifact URL means no claim at all (false negative, never noise).

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const boundary = "----gashSniffBoundary7b2e55";
  const multipartType = "multipart/form-data; boundary=" + boundary;
  const maxSends = 40;
  let sends = 0;

  const filePart = (name, filename, declaredType, content) =>
    "--" + boundary + "\r\n" +
    'Content-Disposition: form-data; name="' + name + '"; filename="' + filename + '"\r\n' +
    "Content-Type: " + declaredType + "\r\n\r\n" +
    content + "\r\n";
  const closeBody = (parts) => parts.join("") + "--" + boundary + "--\r\n";

  // locate walks back from the canary token to the URL delimiter so the
  // artifact can be fetched even when the server rewrites the path.
  const locate = (rawBody, token, base) => {
    const text = String(rawBody || "");
    const idx = text.indexOf(token);
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
    let url = text.slice(start, idx + token.length);
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
    if (String(point.paramLocation || "").toLowerCase() !== "body") {
      continue;
    }
    if (!point.paramName) {
      continue;
    }
    if (String(point.method || "").toUpperCase() !== "POST") {
      continue;
    }
    if (sends + 3 > maxSends) {
      break;
    }
    const canary = probe.canary();
    const token = canary + ".txt";
    // Declaration and extension both say "inert"; the bytes say otherwise.
    const payload = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(' + canary + ')"></svg>';
    const body = closeBody([filePart(point.paramName, token, "application/octet-stream", payload)]);

    sends++;
    const uploadResp = probe.send({
      url: point.url,
      method: point.method,
      paramName: "",
      paramLocation: "body",
      value: body,
      headers: { "Content-Type": multipartType },
    });
    const artifactURL = locate(uploadResp && uploadResp.body, token, point.url);
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
    const controlURL = artifactURL.split(canary).join(canary + "_never");
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
