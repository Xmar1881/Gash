// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package flow

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// testApp çok-adımlı, döner CSRF token'lı ve oturum cookie'li uygulamadır.
type testApp struct {
	mu       sync.Mutex
	nonce    int
	tokens   map[string]bool
	sessions map[string]int // session id -> stage
	name     string
	title    string
	// bypass true ise /done oturumsuz aynı içeriği döner.
	bypass bool
	// xss true ise /done alanları kaçışsız yazar.
	xss bool
	// sqliError true ise title SQLi gibi görününce DB hatası döner.
	sqliError bool
	// leakSession true ise /done oturumsuz login formu döner.
	loginProtected bool
}

func newTestApp() *testApp {
	return &testApp{
		tokens:   make(map[string]bool),
		sessions: make(map[string]int),
	}
}

func (a *testApp) token() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nonce++
	tok := fmt.Sprintf("tok-%d", a.nonce)
	a.tokens[tok] = true
	return tok
}

func (a *testApp) consume(tok string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.tokens[tok] {
		return false
	}
	delete(a.tokens, tok)
	return true
}

func (a *testApp) session(r *http.Request) (string, int) {
	c, err := r.Cookie("sid")
	if err != nil {
		return "", 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return c.Value, a.sessions[c.Value]
}

func (a *testApp) setStage(w http.ResponseWriter, sid string, stage int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions[sid] = stage
}

func (a *testApp) handler() http.Handler {
	mux := http.NewServeMux()
	form := func(action string) string {
		return `<html><body><form method="POST" action="` + action + `">` +
			`<input type="hidden" name="csrf" value="` + a.token() + `">` +
			`<input type="text" name="field">` +
			`<button type="submit">next</button></form></body></html>`
	}
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.nonce++
		sid := fmt.Sprintf("sid-%d", a.nonce)
		a.sessions[sid] = 0
		a.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/"})
		_, _ = io.WriteString(w, form("/step1"))
	})
	mux.HandleFunc("/step1", func(w http.ResponseWriter, r *http.Request) {
		sid, stage := a.session(r)
		if sid == "" || stage != 0 {
			http.Error(w, "no session", http.StatusForbidden)
			return
		}
		if !a.consume(r.FormValue("csrf")) {
			http.Error(w, "csrf token invalid", http.StatusForbidden)
			return
		}
		a.mu.Lock()
		a.name = r.FormValue("field")
		a.mu.Unlock()
		a.setStage(w, sid, 1)
		http.Redirect(w, r, "/step2", http.StatusSeeOther)
	})
	mux.HandleFunc("/step2", func(w http.ResponseWriter, r *http.Request) {
		_, stage := a.session(r)
		if stage != 1 {
			http.Error(w, "no session", http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, form("/finish"))
	})
	mux.HandleFunc("/finish", func(w http.ResponseWriter, r *http.Request) {
		sid, stage := a.session(r)
		if sid == "" || stage != 1 {
			http.Error(w, "no session", http.StatusForbidden)
			return
		}
		if !a.consume(r.FormValue("csrf")) {
			http.Error(w, "csrf token invalid", http.StatusForbidden)
			return
		}
		title := r.FormValue("field")
		a.mu.Lock()
		a.title = title
		bad := a.sqliError && (strings.Contains(title, "'") || strings.Contains(title, "AND"))
		a.mu.Unlock()
		if bad {
			http.Error(w, "You have an error in your SQL syntax near '"+title+"'", http.StatusInternalServerError)
			return
		}
		a.setStage(w, sid, 2)
		http.Redirect(w, r, "/done", http.StatusSeeOther)
	})
	mux.HandleFunc("/done", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		bypass, xss, loginProtected := a.bypass, a.xss, a.loginProtected
		name, title := a.name, a.title
		a.mu.Unlock()
		_, stage := a.session(r)
		if stage != 2 && !bypass {
			if loginProtected {
				_, _ = io.WriteString(w, `<html><body><form method="POST" action="/login">`+
					`<input type="password" name="pw"></form></body></html>`)
				return
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		render := func(v string) string {
			if xss {
				return v
			}
			return strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(v)
		}
		_, _ = io.WriteString(w, "<html><body><h1>Done</h1><p>Name: "+render(name)+
			"</p><p>Title: "+render(title)+"</p>"+
			strings.Repeat("<div>stable content block</div>", 40)+
			"</body></html>")
	})
	return mux
}

// senderFromServer flow.Sender sözleşmesine uyarlanmış test istemcisidir.
func senderFromServer(srv *httptest.Server) Sender {
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return func(ctx context.Context, method, rawURL string, headers map[string]string, payload []byte) (int, http.Header, string, error) {
		var body io.Reader
		if len(payload) > 0 {
			body = strings.NewReader(string(payload))
		}
		req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
		if err != nil {
			return 0, nil, "", err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return 0, nil, "", err
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return 0, nil, "", err
		}
		return resp.StatusCode, resp.Header.Clone(), string(data), nil
	}
}

func discoverTestFlow(t *testing.T, app *testApp) (*Flow, Sender, func()) {
	t.Helper()
	srv := httptest.NewServer(app.handler())
	send := senderFromServer(srv)
	f, err := DiscoverFlow(context.Background(), send, Options{SeedURL: srv.URL + "/start"})
	if err != nil {
		srv.Close()
		t.Fatalf("discover: %v", err)
	}
	return f, send, srv.Close
}

func TestDiscoverFlowTwoSteps(t *testing.T) {
	app := newTestApp()
	f, _, closeFn := discoverTestFlow(t, app)
	defer closeFn()
	if len(f.Steps) != 2 {
		t.Fatalf("2 adım beklenir, got %d (stopped=%s)", len(f.Steps), f.Stopped)
	}
	if f.Steps[0].Method != http.MethodPost || f.Steps[1].Method != http.MethodPost {
		t.Fatalf("POST adımları beklenir: %+v", f.Steps)
	}
	if !strings.Contains(f.Baseline.FinalRaw, "Name:") {
		t.Fatalf("final baseline gövdesi beklenir: %q", f.Baseline.FinalRaw)
	}
	if f.Budget.Used == 0 {
		t.Fatal("bütçe kullanımı izlenmeli")
	}
}

func TestReplayRefreshesCSRFTokens(t *testing.T) {
	app := newTestApp()
	f, send, closeFn := discoverTestFlow(t, app)
	defer closeFn()
	r, err := ReplayFlow(context.Background(), send, f, ReplayOptions{
		StepIndex: 0, Field: "field", Payload: Payload{Value: "changed", Kind: PayloadSQLi},
	})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if r.Stopped != "" {
		t.Fatalf("taze token'lı replay sapmamalı: %s", r.Stopped)
	}
	if len(r.Responses) != 2 {
		t.Fatalf("2 yanıt beklenir, got %d", len(r.Responses))
	}
}

func TestReplayStopsOnBudget(t *testing.T) {
	app := newTestApp()
	f, send, closeFn := discoverTestFlow(t, app)
	defer closeFn()
	r, err := ReplayFlow(context.Background(), send, f, ReplayOptions{
		StepIndex: 0, Field: "field", Payload: Payload{Value: "x", Kind: PayloadSQLi},
		MaxRequests: 1,
	})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if r.Stopped == "" {
		t.Fatal("bütçe tükenince Stopped dolu olmalı")
	}
}

func TestEvaluateSQLiErrorDownstream(t *testing.T) {
	app := newTestApp()
	app.sqliError = true
	f, send, closeFn := discoverTestFlow(t, app)
	defer closeFn()
	r, err := ReplayFlow(context.Background(), send, f, ReplayOptions{
		StepIndex: 1, Field: "field", Payload: Payload{Value: "' AND 1=1--", Kind: PayloadSQLi},
	})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	res := Evaluate(context.Background(), f, r)
	var got *Result
	for i := range res {
		if res[i].Kind == ResultSQLiError {
			got = &res[i]
		}
	}
	if got == nil {
		t.Fatalf("SQLi hata kanıtı beklenir, got %+v", res)
	}
	if got.RuleID != "GASH-004" || got.CWE != "CWE-89" {
		t.Fatalf("GASH-004/CWE-89 beklenir, got %s/%s", got.RuleID, got.CWE)
	}
}

func TestEvaluateReflectedXSSAtLaterStep(t *testing.T) {
	app := newTestApp()
	app.xss = true
	f, send, closeFn := discoverTestFlow(t, app)
	defer closeFn()
	payloads := XSSPayloads("gashmarker1")
	r, err := ReplayFlow(context.Background(), send, f, ReplayOptions{
		StepIndex: 0, Field: "field", Payload: payloads[0],
	})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	res := Evaluate(context.Background(), f, r)
	var got *Result
	for i := range res {
		if res[i].Kind == ResultXSSReflection {
			got = &res[i]
		}
	}
	if got == nil {
		t.Fatalf("XSS yansıma kanıtı beklenir, got %+v", res)
	}
	if got.RuleID != "GASH-001" || got.CWE != "CWE-79" {
		t.Fatalf("GASH-001/CWE-79 beklenir, got %s/%s", got.RuleID, got.CWE)
	}
	if got.Step != 1 {
		t.Fatalf("yansıma alt adımda (1) beklenir, got %d", got.Step)
	}
}

func TestCleanFlowNoErrorOrReflection(t *testing.T) {
	app := newTestApp()
	f, send, closeFn := discoverTestFlow(t, app)
	defer closeFn()
	r, err := ReplayFlow(context.Background(), send, f, ReplayOptions{
		StepIndex: 0, Field: "field", Payload: Payload{Value: "benign", Kind: PayloadSQLi},
	})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	for _, res := range Evaluate(context.Background(), f, r) {
		if res.Kind == ResultSQLiError || res.Kind == ResultXSSReflection {
			t.Fatalf("temiz akışta hata/yansıma bulgusu olmamalı: %+v", res)
		}
	}
}

func TestProbeFlowBypassIdenticalDirectAccess(t *testing.T) {
	app := newTestApp()
	app.bypass = true
	f, send, closeFn := discoverTestFlow(t, app)
	defer closeFn()
	res, used, err := ProbeFlowBypass(context.Background(), send, f, Options{})
	if err != nil {
		t.Fatalf("bypass: %v", err)
	}
	if used < 1 {
		t.Fatalf("bypass check must spend >=1 request, got %d", used)
	}
	if res == nil {
		t.Fatal("oturumsuz aynı içerik GASH-068 adayı üretmeli")
	}
	if res.RuleID != "GASH-068" || res.CWE != "CWE-841" {
		t.Fatalf("GASH-068/CWE-841 beklenir, got %s/%s", res.RuleID, res.CWE)
	}
	if res.Evidence.Artifacts["direct_access"] != "identical" {
		t.Fatalf("direct_access=identical artefaktı beklenir: %+v", res.Evidence.Artifacts)
	}
}

func TestProbeFlowBypassLoginProtectedNoFinding(t *testing.T) {
	app := newTestApp()
	app.loginProtected = true
	f, send, closeFn := discoverTestFlow(t, app)
	defer closeFn()
	res, _, err := ProbeFlowBypass(context.Background(), send, f, Options{})
	if err != nil {
		t.Fatalf("bypass: %v", err)
	}
	if res != nil {
		t.Fatalf("login korumalı akışta bulgu olmamalı: %+v", res)
	}
}

func TestNormalizeMasksTokensAndScripts(t *testing.T) {
	a := `<html><head><style>.x{}</style><script>var t=1;</script></head><body>` +
		`<input type="hidden" name="csrf" value="abc123"><p>hello   world</p></body></html>`
	b := `<html><head><style>.y{}</style><script>var t=2;</script></head><body>` +
		`<input type="hidden" name="csrf" value="zzz999"><p>hello world</p></body></html>`
	if Normalize(a) != Normalize(b) {
		t.Fatalf("normalize token/script farkını maskelemeli:\n%q\n%q", Normalize(a), Normalize(b))
	}
	if Similarity(Normalize(a), Normalize(b)) != 1 {
		t.Fatal("maskelenmiş gövdeler benzer olmalı")
	}
}

func TestSimilarityMaterialDifference(t *testing.T) {
	a := "alpha beta gamma delta epsilon zeta eta theta"
	b := "one two three four five six seven eight"
	if sim := Similarity(a, b); sim >= materialDifference {
		t.Fatalf("tamamen farklı gövdeler maddi sapma sayılmalı, sim=%.3f", sim)
	}
}

func TestDiscoverFlowStepCapAndNoForm(t *testing.T) {
	app := newTestApp()
	srv := httptest.NewServer(app.handler())
	defer srv.Close()
	f, err := DiscoverFlow(context.Background(), senderFromServer(srv), Options{
		SeedURL: srv.URL + "/start", MaxSteps: 1,
	})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(f.Steps) != 1 {
		t.Fatalf("MaxSteps=1 tek adım beklenir, got %d", len(f.Steps))
	}
}

func TestDiscoverFlowLoopStops(t *testing.T) {
	mux := http.NewServeMux()
	var mu sync.Mutex
	tokens := map[string]bool{}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		mu.Lock()
		tok := fmt.Sprintf("t%d", len(tokens))
		tokens[tok] = true
		mu.Unlock()
		_, _ = io.WriteString(w, `<form method="POST" action="/">`+
			`<input type="hidden" name="csrf" value="`+tok+`">`+
			`<input type="text" name="q"></form>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	f, err := DiscoverFlow(context.Background(), senderFromServer(srv), Options{SeedURL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if f.Stopped != "loop" {
		t.Fatalf("loop durdurma nedeni beklenir, got %q (steps=%d)", f.Stopped, len(f.Steps))
	}
}
