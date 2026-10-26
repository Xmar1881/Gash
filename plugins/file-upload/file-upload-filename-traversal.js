/* ---
id: file-upload-filename-traversal
name: File Upload Filename Traversal (serve-back proof)
description: Detects filename path traversal in an upload endpoint by uploading a multipart part whose filename escapes the upload directory, locating the artifact outside that directory, and verifying the payload is served back with an active content type.
author: GASH contributors
severity: high
tags: [file-upload, path-traversal, zip-slip, stored-xss, serve-back]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 76
api_version: "1.0"
tests: tests/fixtures/file-upload-filename-traversal/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/file-upload/file-upload-filename-traversal.js
// What: Tier 2 filename-traversal upload plugin with a serve-back proof.
// Why: The serve-back plugin proves a type-validation gap with a benign name.
//   The traversal variant asks a different question: does the server sanitize
//   the filename itself? The proof is the same two-exchange workflow with a
//   different artifact name ("../../<canary>.html") — the artifact must come
//   back with our canary from a path outside the upload directory, and a
//   sibling name that was never uploaded must stay clean. Without a locatable
//   URL the plugin claims nothing (false negative, never noise).

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const boundary = "----gashTraversalBoundary4d7a91";
  const multipartType = "multipart/form-data; boundary=" + boundary;
  const maxSends = 40;
  let sends = 0;

  const filePart = (name, filename, declaredType, content) =>
    "--" + boundary + "\r\n" +
    'Content-Disposition: form-data; name="' + name + '"; filename="' + filename + '"\r\n' +
    "Content-Type: " + declaredType + "\r\n\r\n" +
    content + "\r\n";
  const closeBody = (parts) => parts.join("") + "--" + boundary + "--\r\n";

  // locate walks back from the canary token to the URL delimiter, so the URL
  // the server handed out can be fetched even after path normalization.
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
    const token = canary + ".html";
    // The traversal lives in the filename, not in the content type: a server
    // that joins the upload directory with the raw name writes outside it.
    const filename = "../../" + token;
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
    // A sibling name that was never uploaded: the control proves the served
    // artifact is ours and not a pre-existing file.
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
