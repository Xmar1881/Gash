// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package loader

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
)

func timingSpec() *plugin.PluginSpec {
	return &plugin.PluginSpec{
		ID: "timing-probe", Name: "Timing probe test", Description: "Timing bindingini dogrulamak icin yeterli uzunlukta aciklama.",
		Severity: plugin.SeverityHigh, Tags: []string{"sqli"}, Safe: false,
		Phase: plugin.PhaseProbe, Order: 50, APIVersion: "1.0",
	}
}

func TestTimingBindingAccept(t *testing.T) {
	src := `
function run(probe, ctx) {
  const d = [];
  const c = [];
  for (let i = 0; i < 3; i++) {
    d.push({status: 200, headers: {}, body: "slow", url: "http://x/", rttMs: 5200});
    c.push({status: 200, headers: {}, body: "fast", url: "http://x/", rttMs: 40});
  }
  const ev = host.oracles.timing(d, c, {min_delay_ms: 5000, repeats: 3});
  if (ev) {
    const pts = ctx.injectionPoints();
    host.candidate(pts[0], "timing", ev);
  }
  return [];
}`
	env := &JSEnv{
		Points: []JSPoint{{URL: "http://x/", Method: "GET", ParamName: "id", ParamLocation: "query"}},
		Send:   func(p JSPoint) (JSResponse, error) { return JSResponse{Status: 200, Body: "ok", URL: p.URL}, nil },
	}
	got, err := ExecuteJS(context.Background(), timingSpec(), src, env, 10*time.Second)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(got) != 1 || got[0].Candidate.OracleName != "timing" {
		t.Fatalf("timing kabul bekleniyordu: %+v", got)
	}
	if string(got[0].Evidence.ConfidenceContribution) != "firm" {
		t.Fatalf("timing tavanı firm olmalı: %s", got[0].Evidence.ConfidenceContribution)
	}
}

func TestTimingBindingRejectOnJitter(t *testing.T) {
	src := `
function run(probe, ctx) {
  const d = [{status: 200, headers: {}, body: "a", url: "http://x/", rttMs: 60}];
  const c = [{status: 200, headers: {}, body: "a", url: "http://x/", rttMs: 55}];
  const ev = host.oracles.timing(d, c, {min_delay_ms: 5000, repeats: 3});
  if (ev) {
    const pts = ctx.injectionPoints();
    host.candidate(pts[0], "timing", ev);
  }
  return [];
}`
	env := &JSEnv{
		Points: []JSPoint{{URL: "http://x/", Method: "GET", ParamName: "id", ParamLocation: "query"}},
		Send:   func(p JSPoint) (JSResponse, error) { return JSResponse{Status: 200, Body: "ok", URL: p.URL}, nil },
	}
	got, err := ExecuteJS(context.Background(), timingSpec(), src, env, 10*time.Second)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("jitter içi timing reddedilmeli: %+v", got)
	}
}

func TestExecutionBindingFirmMax(t *testing.T) {
	src := `
function run(probe, ctx) {
  const pts = ctx.injectionPoints();
  const resp = probe.send(pts[0].withValue("x"));
  const ev = host.oracles.execution(resp);
  if (ev) {
    host.candidate(pts[0], "dom-xss", ev);
  }
  return [];
}`
	env := &JSEnv{
		Points: []JSPoint{{URL: "http://x/", Method: "GET", ParamName: "q", ParamLocation: "query"}},
		Send: func(p JSPoint) (JSResponse, error) {
			return JSResponse{Status: 200, Body: `<div id="a"></div><script>el.innerHTML = location.hash;</script>`, URL: p.URL}, nil
		},
	}
	spec := timingSpec()
	spec.ID = "dom-sink-probe"
	got, err := ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(got) != 1 || got[0].Candidate.OracleName != "execution" {
		t.Fatalf("execution firm bekleniyordu: %+v", got)
	}
	if string(got[0].Evidence.ConfidenceContribution) != "firm" {
		t.Fatalf("headless yokken tavan firm: %s", got[0].Evidence.ConfidenceContribution)
	}
}

func TestBrowserExecutionBindingConfirmed(t *testing.T) {
	src := `
function run(probe, ctx) {
  const pts = ctx.injectionPoints();
  const ev = host.oracles.browserExecution(pts[0], "PAYLOAD");
  if (ev) {
    host.candidate(pts[0], "dom-xss", ev);
  }
  return [];
}`
	var gotPoint JSPoint
	var gotPayload string
	env := &JSEnv{
		Points: []JSPoint{{URL: "http://x/#/search", Method: "GET", ParamName: "q", ParamLocation: "fragment"}},
		BrowserProbe: func(p JSPoint, payload string) (bool, bool, bool, error) {
			gotPoint, gotPayload = p, payload
			return true, true, true, nil
		},
	}
	spec := timingSpec()
	spec.ID = "dom-browser-probe"
	got, err := ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(got) != 1 || got[0].Candidate.OracleName != "execution" {
		t.Fatalf("browser execution candidate expected: %+v", got)
	}
	if gotPoint.ParamLocation != "fragment" || gotPayload != "PAYLOAD" {
		t.Fatalf("browser probe received wrong point/payload: %+v %q", gotPoint, gotPayload)
	}
	if string(got[0].Evidence.ConfidenceContribution) != "confirmed" {
		t.Fatalf("browser execution must confirm: %s", got[0].Evidence.ConfidenceContribution)
	}
	if got[0].Evidence.Artifacts["browser"] != "execution" {
		t.Fatalf("browser artifact missing: %+v", got[0].Evidence.Artifacts)
	}
}

func executeDOMSinkPlugin(t *testing.T, points []JSPoint, body string) ([]JSCandidate, []JSPoint) {
	t.Helper()
	src, err := os.ReadFile("../../../plugins/xss/dom-sink-basic.js")
	if err != nil {
		t.Fatalf("read plugin: %v", err)
	}
	var probed []JSPoint
	env := &JSEnv{
		Points: points,
		Send: func(p JSPoint) (JSResponse, error) {
			return JSResponse{Status: 200, Body: body, URL: p.URL}, nil
		},
		BrowserProbe: func(p JSPoint, payload string) (bool, bool, bool, error) {
			probed = append(probed, p)
			if p.ParamLocation != "hash" {
				return false, false, false, nil
			}
			return true, true, true, nil
		},
	}
	spec := timingSpec()
	spec.ID = "dom-sink-basic"
	spec.Tests = "tests/fixtures/dom-sink-basic/"
	got, err := ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	return got, probed
}

func TestDOMSourceSinkLinkRequiresSameInlineScript(t *testing.T) {
	linked := `<div id="o"></div><script>const h=location.hash;document.getElementById("o").innerHTML=h;</script>`
	if !domSourceSinkLinked(linked, "location.hash", "innerhtml") {
		t.Fatal("same-script source/sink must correlate")
	}
	split := `<script>const h=location.hash;</script><script>document.getElementById("o").innerHTML=h;</script>`
	if domSourceSinkLinked(split, "location.hash", "innerhtml") {
		t.Fatal("separate scripts must not claim a static data flow")
	}
	if detectDOMSink(`<script>const h=location.hash;</script>`) != "" {
		t.Fatal("location.hash is a source, not a sink")
	}
}

func TestDOMSinkBasicHashSourceTestsRawHashPoint(t *testing.T) {
	body := `<div id="o"></div><script>const h=location.hash;document.getElementById("o").innerHTML=h;</script>`
	points := []JSPoint{{URL: "http://x/dom?next=x", Method: "GET", ParamName: "next", ParamLocation: "query"}}
	got, probed := executeDOMSinkPlugin(t, points, body)
	if len(got) != 1 {
		t.Fatalf("one hash candidate expected: %+v", got)
	}
	c := got[0].Candidate
	if c.InjectionPoint.ParamLocation != "hash" || c.InjectionPoint.URL != "http://x/dom?next=x" {
		t.Fatalf("query point must become an independent raw-hash test: %+v", c.InjectionPoint)
	}
	if c.InjectionPoint.Value == "" || c.InjectionPoint.SourceKind != "hash" || c.InjectionPoint.TestID == "" {
		t.Fatalf("hash test identity missing: %+v", c.InjectionPoint)
	}
	if len(probed) != 1 || probed[0].ParamLocation != "hash" {
		t.Fatalf("browser must probe hash, never query: %+v", probed)
	}
	ev := got[0].Evidence
	if ev.Artifacts["source"] != "location.hash" || ev.Artifacts["sink"] != "innerhtml" {
		t.Fatalf("source/sink evidence missing: %+v", ev.Artifacts)
	}
	if ev.Artifacts["source_sink_linked"] != "true" || ev.Artifacts["execution_confirmed"] != "true" {
		t.Fatalf("evidence chain incomplete: %+v", ev.Artifacts)
	}
	if ev.Artifacts["execution"] != "browser-confirmed" {
		t.Fatalf("reporter-compatible execution evidence missing: %+v", ev.Artifacts)
	}
}

func TestDOMSinkBasicQueryAndHashPointsDedupe(t *testing.T) {
	body := `<div id="o"></div><script>const h=location.hash;document.getElementById("o").innerHTML=h;</script>`
	points := []JSPoint{
		{URL: "http://x/dom?next=x", Method: "GET", ParamName: "next", ParamLocation: "query"},
		{URL: "http://x/dom", Method: "GET", ParamLocation: "hash"},
	}
	got, probed := executeDOMSinkPlugin(t, points, body)
	if len(got) != 1 {
		t.Fatalf("query and hash points must dedupe to one raw-hash test: %+v", got)
	}
	if got[0].Candidate.InjectionPoint.ParamLocation != "hash" {
		t.Fatalf("deduped candidate must be the hash test: %+v", got[0].Candidate.InjectionPoint)
	}
	if len(probed) != 2 || probed[0].ParamLocation != "hash" || probed[1].ParamLocation != "hash" {
		t.Fatalf("both searches must target the raw hash: %+v", probed)
	}
	if got[0].Evidence.Artifacts["source_sink_linked"] != "true" {
		t.Fatalf("hash evidence must retain the static chain: %+v", got[0].Evidence.Artifacts)
	}
}

func TestDOMSinkBasicQuerySourceDoesNotBecomeHash(t *testing.T) {
	body := `<script>const q=location.search;document.write(q);</script>`
	points := []JSPoint{{URL: "http://x/dom?q=x", Method: "GET", ParamName: "q", ParamLocation: "query"}}
	src, err := os.ReadFile("../../../plugins/xss/dom-sink-basic.js")
	if err != nil {
		t.Fatalf("read plugin: %v", err)
	}
	var probed []JSPoint
	env := &JSEnv{
		Points: points,
		Send:   func(p JSPoint) (JSResponse, error) { return JSResponse{Status: 200, Body: body, URL: p.URL}, nil },
		BrowserProbe: func(p JSPoint, payload string) (bool, bool, bool, error) {
			probed = append(probed, p)
			if p.ParamLocation != "query" {
				return false, false, false, nil
			}
			return true, true, true, nil
		},
	}
	spec := timingSpec()
	spec.ID = "dom-sink-basic"
	spec.Tests = "tests/fixtures/dom-sink-basic/"
	got, err := ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(got) != 1 || got[0].Candidate.InjectionPoint.ParamLocation != "query" {
		t.Fatalf("query candidate expected: %+v", got)
	}
	if len(probed) != 1 || probed[0].ParamLocation != "query" {
		t.Fatalf("browser must probe query, never hash: %+v", probed)
	}
	if got[0].Candidate.InjectionPoint.SourceKind != "query" {
		t.Fatalf("query test identity wrong: %+v", got[0].Candidate.InjectionPoint)
	}
}

func TestDOMSinkBasicNodeInsertionIsNotExecution(t *testing.T) {
	points := []JSPoint{{URL: "http://x/dom", Method: "GET", ParamName: "", ParamLocation: "hash"}}
	src, err := os.ReadFile("../../../plugins/xss/dom-sink-basic.js")
	if err != nil {
		t.Fatalf("read plugin: %v", err)
	}
	env := &JSEnv{
		Points: points,
		BrowserProbe: func(p JSPoint, payload string) (bool, bool, bool, error) {
			return true, false, true, nil
		},
	}
	spec := timingSpec()
	spec.ID = "dom-sink-basic"
	spec.Tests = "tests/fixtures/dom-sink-basic/"
	got, err := ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("node insertion without execution must not confirm: %+v", got)
	}
}

func TestExecutionBindingNoSink(t *testing.T) {
	src := `
function run(probe, ctx) {
  const pts = ctx.injectionPoints();
  const resp = probe.send(pts[0].withValue("x"));
  const ev = host.oracles.execution(resp);
  if (ev) {
    host.candidate(pts[0], "dom-xss", ev);
  }
  return [];
}`
	env := &JSEnv{
		Points: []JSPoint{{URL: "http://x/", Method: "GET", ParamName: "q", ParamLocation: "query"}},
		Send: func(p JSPoint) (JSResponse, error) {
			return JSResponse{Status: 200, Body: `<p>temiz</p>`, URL: p.URL}, nil
		},
	}
	spec := timingSpec()
	spec.ID = "dom-clean"
	got, err := ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("sink yokken bulgu olmamalı: %+v", got)
	}
}
