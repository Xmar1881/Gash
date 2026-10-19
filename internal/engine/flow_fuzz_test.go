// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/probe"
)

// flowTestApp iki adımlı, CSRF token'lı ve oturumlu test uygulamasıdır.
// What: /start → /step1 → /finish → /done akışı; isteğe bağlı SQLi hatası,
// XSS yansıması ve oturumsuz doğrudan erişim.
// Why: Motorun akış keşfi/replay/değerlendirme hattını gerçek HTTP üzerinden
// deterministik olarak sınar (dış ağ yok).
type flowTestApp struct {
	mu       sync.Mutex
	nonce    int
	tokens   map[string]bool
	sessions map[string]int
	name     string
	title    string
	sqli     bool
	xss      bool
	bypass   bool
	requests atomic.Int64
}

func newFlowTestApp() *flowTestApp {
	return &flowTestApp{tokens: map[string]bool{}, sessions: map[string]int{}}
}

func (a *flowTestApp) token() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nonce++
	tok := fmt.Sprintf("tok-%d", a.nonce)
	a.tokens[tok] = true
	return tok
}

func (a *flowTestApp) consume(tok string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.tokens[tok] {
		return false
	}
	delete(a.tokens, tok)
	return true
}

func (a *flowTestApp) stage(r *http.Request) int {
	c, err := r.Cookie("sid")
	if err != nil {
		return -1
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessions[c.Value]
}

func (a *flowTestApp) setStage(r *http.Request, stage int) {
	c, err := r.Cookie("sid")
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions[c.Value] = stage
}

func (a *flowTestApp) handler() http.Handler {
	mux := http.NewServeMux()
	form := func(action string) string {
		return `<html><body><form method="POST" action="` + action + `">` +
			`<input type="hidden" name="csrf" value="` + a.token() + `">` +
			`<input type="text" name="field"></form></body></html>`
	}
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		a.requests.Add(1)
		a.mu.Lock()
		a.nonce++
		sid := fmt.Sprintf("sid-%d", a.nonce)
		a.sessions[sid] = 0
		a.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/"})
		_, _ = io.WriteString(w, form("/step1"))
	})
	mux.HandleFunc("/step1", func(w http.ResponseWriter, r *http.Request) {
		a.requests.Add(1)
		if a.stage(r) != 0 || !a.consume(r.FormValue("csrf")) {
			http.Error(w, "csrf token invalid", http.StatusForbidden)
			return
		}
		a.mu.Lock()
		a.name = r.FormValue("field")
		a.mu.Unlock()
		a.setStage(r, 1)
		http.Redirect(w, r, "/step2", http.StatusSeeOther)
	})
	mux.HandleFunc("/step2", func(w http.ResponseWriter, r *http.Request) {
		a.requests.Add(1)
		if a.stage(r) != 1 {
			http.Error(w, "no session", http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, form("/finish"))
	})
	mux.HandleFunc("/finish", func(w http.ResponseWriter, r *http.Request) {
		a.requests.Add(1)
		if a.stage(r) != 1 || !a.consume(r.FormValue("csrf")) {
			http.Error(w, "csrf token invalid", http.StatusForbidden)
			return
		}
		title := r.FormValue("field")
		a.mu.Lock()
		a.title = title
		sqli := a.sqli && (strings.Contains(title, "'") || strings.Contains(title, "AND"))
		a.mu.Unlock()
		if sqli {
			http.Error(w, "You have an error in your SQL syntax near '"+title+"'", http.StatusInternalServerError)
			return
		}
		a.setStage(r, 2)
		http.Redirect(w, r, "/done", http.StatusSeeOther)
	})
	mux.HandleFunc("/done", func(w http.ResponseWriter, r *http.Request) {
		a.requests.Add(1)
		a.mu.Lock()
		name, title, xss, bypass := a.name, a.title, a.xss, a.bypass
		a.mu.Unlock()
		authenticated := a.stage(r) == 2
		if !authenticated && !bypass {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !authenticated {
			// Oturumsuz doğrudan erişimde akış durumu yoktur: temiz baseline
			// içeriği döner (gerçek dünyada oturumdan gelen değerler boştur).
			name, title = "", ""
		}
		render := func(v string) string {
			if xss {
				return v
			}
			return strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(v)
		}
		_, _ = io.WriteString(w, "<html><body><h1>Done</h1><p>Name: "+render(name)+
			"</p><p>Title: "+render(title)+"</p>"+
			strings.Repeat("<div>stable content block</div>", 40)+"</body></html>")
	})
	return mux
}

// flowHarness motor + politika istemcisi kurar (dış ağ yok).
func flowHarness(t *testing.T, active bool) (*Engine, *probe.Client) {
	t.Helper()
	policy := plugin.NewPolicySession(plugin.PolicyConfig{
		MaxRequestsPerTarget: 1000,
		MaxRequestsTotal:     10000,
		RatePerSecond:        0,
	}, nil)
	client := probe.NewClient(probe.Options{Policy: policy})
	cfg := DefaultConfig()
	cfg.Active = active
	cfg.FlowMaxSteps = 4
	cfg.FlowProbes = 2
	return New(plugin.NewRegistry(), cfg), client
}

// TestRunFlowFuzzSQLiDownstream: akıştaki alt adım SQL hatası GASH-004
// tentative (R-06) bulgusu üretir; sentetik spec plugin sayısını etkilemez.
func TestRunFlowFuzzSQLiDownstream(t *testing.T) {
	app := newFlowTestApp()
	app.sqli = true
	srv := httptest.NewServer(app.handler())
	defer srv.Close()

	e, client := flowHarness(t, true)
	e.cfg.FlowSeed = srv.URL + "/start"
	got, skipped, stats := e.runFlowFuzz(context.Background(), srv.URL, client)
	if len(skipped) != 0 {
		t.Fatalf("bulgu varken skip beklenmez: %+v", skipped)
	}
	if stats["flow_steps"] != 2 {
		t.Fatalf("2 adım beklenir: %+v", stats)
	}
	var sqli *struct {
		rule, cwe string
		sev       plugin.Severity
		conf      plugin.Confidence
	}
	for _, f := range got {
		if f.RuleID == "GASH-004" {
			sqli = &struct {
				rule, cwe string
				sev       plugin.Severity
				conf      plugin.Confidence
			}{f.RuleID, f.CWE, f.Severity, f.Confidence}
		}
	}
	if sqli == nil {
		t.Fatalf("GASH-004 beklenir, got %d bulgu: %+v", len(got), got)
	}
	if sqli.cwe != "CWE-89" || sqli.sev != plugin.SeverityMedium || sqli.conf != plugin.ConfidenceTentative {
		t.Fatalf("tentative/medium CWE-89 beklenir, got %+v", sqli)
	}
	if stats["flow_findings"] != len(got) || stats["flow_replays"] == 0 {
		t.Fatalf("sayaçlar tutarsız: %+v", stats)
	}
}

// TestRunFlowFuzzXSSReflection: yansıma kanaryası alt adımda yürütülebilir
// bağlamda görününce GASH-001 tentative bulgusu üretilir.
func TestRunFlowFuzzXSSReflection(t *testing.T) {
	app := newFlowTestApp()
	app.xss = true
	srv := httptest.NewServer(app.handler())
	defer srv.Close()

	e, client := flowHarness(t, true)
	e.cfg.FlowSeed = srv.URL + "/start"
	got, _, _ := e.runFlowFuzz(context.Background(), srv.URL, client)
	found := false
	for _, f := range got {
		if f.RuleID == "GASH-001" {
			found = true
			if f.CWE != "CWE-79" || f.Confidence != plugin.ConfidenceTentative {
				t.Fatalf("GASH-001 tentative/CWE-79 beklenir: %+v", f)
			}
		}
	}
	if !found {
		t.Fatalf("GASH-001 beklenir, got %d bulgu", len(got))
	}
}

// TestRunFlowFuzzBypassCheck: ≥2 adımlı akışta oturumsuz doğrudan erişim
// ekranı koşar ve GASH-068 tentative üretir.
func TestRunFlowFuzzBypassCheck(t *testing.T) {
	app := newFlowTestApp()
	app.bypass = true
	srv := httptest.NewServer(app.handler())
	defer srv.Close()

	e, client := flowHarness(t, true)
	e.cfg.FlowSeed = srv.URL + "/start"
	got, _, stats := e.runFlowFuzz(context.Background(), srv.URL, client)
	if stats["flow_bypass_checked"] != 1 {
		t.Fatalf("bypass ekranı koşmalı: %+v", stats)
	}
	found := false
	for _, f := range got {
		if f.RuleID == "GASH-068" {
			found = true
			if f.CWE != "CWE-841" || f.Confidence != plugin.ConfidenceTentative {
				t.Fatalf("GASH-068 tentative/CWE-841 beklenir: %+v", f)
			}
		}
	}
	if !found {
		t.Fatalf("GASH-068 beklenir, got %d bulgu: %+v", len(got), got)
	}
}

// TestRunFlowFuzzNoFormHonestSkip: form yoksa tek dürüst skip; bulgu yok.
func TestRunFlowFuzzNoFormHonestSkip(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "<html><body>no forms here</body></html>")
	}))
	defer srv.Close()

	e, client := flowHarness(t, true)
	e.cfg.FlowSeed = srv.URL + "/start"
	got, skipped, stats := e.runFlowFuzz(context.Background(), srv.URL, client)
	if len(got) != 0 {
		t.Fatalf("bulgu olmamalı: %+v", got)
	}
	if len(skipped) != 1 || skipped[0].PluginID != "flow" ||
		!strings.Contains(skipped[0].Reason, "flow-discovery") {
		t.Fatalf("tek dürüst flow skip beklenir: %+v", skipped)
	}
	if stats["flow_steps"] != 0 || stats["flow_replays"] != 0 {
		t.Fatalf("keşif başarısızken sayaçlar sıfır olmalı: %+v", stats)
	}
	if hits.Load() == 0 {
		t.Fatal("keşif en az bir GET atmalı")
	}
}

// TestRunFlowFuzzScopePreflight: kapsam-dışı seed'e istek gitmez (fail-closed).
func TestRunFlowFuzzScopePreflight(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "<html><body>ok</body></html>")
	}))
	defer srv.Close()

	e, client := flowHarness(t, true)
	e.cfg.Scope = []string{"203.0.113.0/24"}
	e.cfg.FlowSeed = srv.URL + "/start"
	got, skipped, stats := e.runFlowFuzz(context.Background(), srv.URL, client)
	if len(got) != 0 || stats["flow_steps"] != 0 {
		t.Fatalf("kapsam dışında iş yapılmamalı: %+v %+v", got, stats)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0].Reason, "outside scope") {
		t.Fatalf("kapsam skip'i beklenir: %+v", skipped)
	}
	if hits.Load() != 0 {
		t.Fatalf("kapsam-dışı seed'e istek gitmemeli, got %d", hits.Load())
	}
}

// TestRunFlowFuzzRequiresSeed: seed yoksa hiçbir istek/sayaç üretilmez.
func TestRunFlowFuzzRequiresSeed(t *testing.T) {
	e, client := flowHarness(t, true)
	got, skipped, stats := e.runFlowFuzz(context.Background(), "http://127.0.0.1:1", client)
	if len(got) != 0 || len(skipped) != 0 {
		t.Fatalf("seed'siz çıktı olmamalı: %+v %+v", got, skipped)
	}
	if stats["flow_seed"] != 0 || stats["flow_requests"] != 0 {
		t.Fatalf("seed'siz sayaçlar sıfır olmalı: %+v", stats)
	}
}

// TestRunFlowFuzzInactive: --active yoksa motor akış koşmaz (scan_exec kapısı
// ayrıca korur; burada fonksiyonun kendisi de seed'siz davranır).
func TestRunFlowFuzzInactive(t *testing.T) {
	app := newFlowTestApp()
	srv := httptest.NewServer(app.handler())
	defer srv.Close()

	e, client := flowHarness(t, false)
	e.cfg.FlowSeed = srv.URL + "/start"
	got, _, stats := e.runFlowFuzz(context.Background(), srv.URL, client)
	if len(got) != 0 || stats["flow_steps"] != 0 {
		t.Fatalf("inactive modda akış koşmamalı: %+v %+v", got, stats)
	}
	if app.requests.Load() != 0 {
		t.Fatalf("inactive modda istek gitmemeli, got %d", app.requests.Load())
	}
}
