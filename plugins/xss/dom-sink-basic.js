/* ---
id: dom-sink-basic
name: DOM Sink (static + browser-confirmed)
description: Detects URL-controlled DOM sinks through the execution oracle; hash routes are exercised in a real browser when available.
author: Gash contributors
severity: medium
tags: [xss, dom, client]
safe: true
deep: false
active: false
requires_auth: false
phase: probe
order: 45
api_version: "1.0"
tests: tests/fixtures/dom-sink-basic/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / Gash contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/xss/dom-sink-basic.js
// What: Tier 2 DOM sink scanner backed by ExecutionOracle.
// Why: Static sink/source analysis caps at firm; fragment queries never reach
//   the server, so those points require a real browser probe.

const DOM_XSS_PAYLOAD = '"><iframe src="javascript:alert(window.__gashCanary=true)"></iframe>';

function routeKey(raw, location) {
  const s = String(raw || "");
  const hash = s.indexOf("#");
  const base = (hash >= 0 ? s.slice(0, hash) : s).split("?")[0];
  if (String(location || "").toLowerCase() === "hash") {
    return base;
  }
  const frag = (hash >= 0 ? s.slice(hash) : "").split("?")[0];
  return base + frag;
}

function evidenceKey(point, location, ev) {
  return [
    routeKey(point.url, location), point.method, location,
    ev.sink || "", ev.source || "",
  ].join("|");
}

function sourceKind(source) {
  const s = String(source || "").toLowerCase();
  if (!s) return "";
  if (s.indexOf("hash") >= 0) return "hash";
  if (s.indexOf("search") >= 0 || s.indexOf("urlsearchparams") >= 0) return "query";
  if (s.indexOf("location.href") >= 0 || s.indexOf("document.url") >= 0 ||
      s.indexOf("document.location") >= 0 || s === "location") return "url";
  return "";
}

function baseURL(raw) {
  const s = String(raw || "");
  const cut = s.indexOf("#");
  return cut >= 0 ? s.slice(0, cut) : s;
}

function hashPoint(point, value) {
  const base = baseURL(point.url);
  return {
    url: base,
    method: point.method || "GET",
    paramName: "",
    paramLocation: "hash",
    value: value,
    sourceKind: "hash",
    testId: ["point", "hash", "", point.method || "GET", base].join("|"),
  };
}

function browserCheck(point, ev, linked) {
  if (!host.oracles.browserExecution) return null;
  return host.oracles.browserExecution(point, DOM_XSS_PAYLOAD, {
    sink: ev && ev.sink ? ev.sink : "",
    source: ev && ev.source ? ev.source : "",
    correlated: linked,
  });
}

function linkedEvidence(ev) {
  if (!ev) return false;
  if (!ev.source || !ev.sink) return true;
  return String(ev.source_sink_linked || "") !== "false";
}

function basePageEvidence(probe, point) {
  try {
    const resp = probe.send({
      url: baseURL(point.url),
      method: point.method || "GET",
      paramName: "",
      paramLocation: "query",
      value: "",
    });
    if (!resp) return null;
    return host.oracles.execution(resp);
  } catch (e) {
    return null;
  }
}

function emit(candidates, seen, point, location, ev) {
  const key = evidenceKey(point, location, ev);
  if (seen.has(key)) return;
  seen.add(key);
  candidates.push(host.candidate(point, "dom-xss", ev));
}

function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const candidates = [];
  const seen = new Set();
  for (const point of points) {
    const location = String(point.paramLocation || "").toLowerCase();
    const payload = DOM_XSS_PAYLOAD;
    const target = point.withValue(payload);
    if (location === "fragment" || location === "hash") {
      if (!host.oracles.browserExecution) {
        continue;
      }
      const staticEv = location === "hash" ? basePageEvidence(probe, target) : null;
      const linked = linkedEvidence(staticEv);
      const confirmed = browserCheck(target, staticEv, linked);
      const ev = confirmed || staticEv;
      if (ev) {
        emit(candidates, seen, target, location, ev);
      }
      continue;
    }
    const resp = probe.send(target);
    const ev = host.oracles.execution(resp);
    if (!ev) {
      continue;
    }
    const linked = linkedEvidence(ev);
    const srcKind = sourceKind(ev.source);

    if (srcKind === "hash") {
      const hp = hashPoint(point, payload);
      if (!host.oracles.browserExecution) {
        if (linked) {
          emit(candidates, seen, hp, "hash", ev);
        }
        continue;
      }
      const confirmed = browserCheck(hp, ev, linked);
      emit(candidates, seen, hp, "hash", confirmed || ev);
      continue;
    }
    if (location !== "query") {
      if (!linked) {
        continue;
      }
      emit(candidates, seen, target, location, ev);
      continue;
    }

    let finalEv = ev;
    if (host.oracles.browserExecution) {
      const confirmed = browserCheck(target, ev, linked);
      if (confirmed) {
        finalEv = confirmed;
      }
    }
    if (finalEv === ev && !linked) {
      continue;
    }
    emit(candidates, seen, target, location, finalEv);
  }
  return candidates;
}
