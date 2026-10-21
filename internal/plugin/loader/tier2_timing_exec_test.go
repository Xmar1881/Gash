// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package loader

import (
	"context"
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
