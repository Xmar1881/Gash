// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package loader

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
)

func oobSpec() *plugin.PluginSpec {
	return &plugin.PluginSpec{
		ID: "ssrf-oob-probe", Name: "SSRF OOB probe test", Description: "OOB bindinglerini dogrulamak icin yeterli uzunlukta aciklama.",
		Severity: plugin.SeverityHigh, Tags: []string{"ssrf", "oob"}, Safe: false,
		Phase: plugin.PhaseProbe, Order: 60, APIVersion: "1.0",
	}
}

// oobAnySrc ships one variant, waits through the shared-window binding and
// maps the matched correlation back to the point that fired.
const oobAnySrc = `
function run(probe, ctx) {
  const pts = ctx.injectionPoints();
  const oob = host.oob.generate("http");
  if (!oob) { return []; }
  const payload = "http://" + oob.domain + "/ssrf?t=" + oob.correlationId;
  probe.send(pts[0].withValue(payload));
  const ev = host.oracles.oobAny([oob.correlationId], oob.namespace);
  if (ev && String(ev.correlationId) === String(oob.correlationId)) {
    host.candidate(pts[0].withValue(payload), "ssrf-blind", ev);
  }
  return [];
}`

// TestJSGenerateUsesProviderBindings: token üretici ve domain/URL gerçek
// self-hosted sağlayıcıdan gelir (oob.example fallback'i canlıda kullanılmaz).
func TestJSGenerateUsesProviderBindings(t *testing.T) {
	src := `
function run(probe, ctx) {
  const oob = host.oob.generate("http");
  if (!oob) { host.candidate(ctx.injectionPoints()[0], "ssrf-blind", null); return []; }
  if (oob.domain !== "c_live.oob.test") { throw "domain yanlis: " + oob.domain; }
  if (oob.url !== "http://oob.test/cb/c_live") { throw "url yanlis: " + oob.url; }
  if (oob.correlationId !== "c_live") { throw "corr yanlis: " + oob.correlationId; }
  if (oob.namespace !== "scan") { throw "ns yanlis: " + oob.namespace; }
  return [];
}`
	env := &JSEnv{
		Points:         []JSPoint{{URL: "http://x/", Method: "GET", ParamName: "q", ParamLocation: "query"}},
		Send:           func(p JSPoint) (JSResponse, error) { return JSResponse{Status: 200, URL: p.URL}, nil },
		OOBEnabled:     true,
		OOBNamespace:   "scan",
		OOBCorrelation: "c_live",
		OOBDomain:      func(corr string) string { return corr + ".oob.test" },
		OOBURL:         func(corr string) string { return "http://oob.test/cb/" + corr },
	}
	if _, err := ExecuteJS(context.Background(), oobSpec(), src, env, 5*time.Second); err != nil {
		t.Fatalf("execute: %v", err)
	}
}

// TestJSOobAnyConfirmsMatchedToken: callback eşleşen tek token confirmed bulgu
// üretir; gerçek domain payload'a girer.
func TestJSOobAnyConfirmsMatchedToken(t *testing.T) {
	var sentValue string
	env := &JSEnv{
		Points: []JSPoint{{URL: "http://x/", Method: "GET", ParamName: "q", ParamLocation: "query"}},
		Send: func(p JSPoint) (JSResponse, error) {
			sentValue = p.Value
			return JSResponse{Status: 200, URL: p.URL}, nil
		},
		OOBEnabled:     true,
		OOBNamespace:   "scan",
		OOBCorrelation: "c_js1",
		OOBDomain:      func(corr string) string { return corr + ".oob.test" },
		OOBURL:         func(corr string) string { return "http://oob.test/cb/" + corr },
		OOBCallbackSeenAny: func(ids []string) []string {
			if len(ids) == 1 && ids[0] == "c_js1" {
				return ids
			}
			return nil
		},
	}
	got, err := ExecuteJS(context.Background(), oobSpec(), oobAnySrc, env, 5*time.Second)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("tek confirmed bulgu bekleniyordu: %+v", got)
	}
	if got[0].Candidate.OracleName != "oob" {
		t.Fatalf("ref eşlemesi oob olmalı: %s", got[0].Candidate.OracleName)
	}
	if !strings.Contains(sentValue, "c_js1.oob.test") {
		t.Fatalf("payload gerçek domaini taşımalı: %q", sentValue)
	}
	if got[0].Evidence == nil || string(got[0].Evidence.ConfidenceContribution) != "confirmed" {
		t.Fatalf("confirmed kanıt bekleniyordu: %+v", got[0].Evidence)
	}
	if got[0].Evidence.Artifacts["correlation"] != "c_js1" {
		t.Fatalf("kanıt correlation taşımalı: %+v", got[0].Evidence.Artifacts)
	}
}

// TestJSOobAnyNoMatchNoFinding: callback yoksa bulgu YOK (tentative dahil).
func TestJSOobAnyNoMatchNoFinding(t *testing.T) {
	env := &JSEnv{
		Points:             []JSPoint{{URL: "http://x/", Method: "GET", ParamName: "q", ParamLocation: "query"}},
		Send:               func(p JSPoint) (JSResponse, error) { return JSResponse{Status: 200, URL: p.URL}, nil },
		OOBEnabled:         true,
		OOBNamespace:       "scan",
		OOBCorrelation:     "c_js2",
		OOBDomain:          func(corr string) string { return corr + ".oob.test" },
		OOBURL:             func(corr string) string { return "http://oob.test/cb/" + corr },
		OOBCallbackSeenAny: func([]string) []string { return nil },
	}
	got, err := ExecuteJS(context.Background(), oobSpec(), oobAnySrc, env, 5*time.Second)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("callback yoksa bulgu olmamalı: %+v", got)
	}
}

// TestJSGenerateDisabledSkipsHonestly: OOB kapalıyken generate null döner,
// plugin hiç istek atmadan çıkar (skip disiplini).
func TestJSGenerateDisabledSkipsHonestly(t *testing.T) {
	sends := 0
	env := &JSEnv{
		Points:     []JSPoint{{URL: "http://x/", Method: "GET", ParamName: "q", ParamLocation: "query"}},
		Send:       func(p JSPoint) (JSResponse, error) { sends++; return JSResponse{Status: 200, URL: p.URL}, nil },
		OOBEnabled: false,
	}
	got, err := ExecuteJS(context.Background(), oobSpec(), oobAnySrc, env, 5*time.Second)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(got) != 0 || sends != 0 {
		t.Fatalf("kapalı OOB'da istek/bulgu olmamalı: got=%d sends=%d", len(got), sends)
	}
}
