// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: internal/discovery/content-discovery_test.go
// What: Mock HTTP server ile FP/FN + smart-recurse tavan testleri.
// Why: Admin 200+keyword confirmed, soft-404 catch-all reject, .git/HEAD
// HEAD-only tentative, çıplak 200 tentative, derinlik tavanı enforcement.

package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/probe"
)

// mockLog isteki günlüğüdür (hangi path hangi metotla vuruldu).
type mockLog struct {
	mu      sync.Mutex
	methods map[string][]string
}

func (l *mockLog) record(path, method string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.methods == nil {
		l.methods = map[string][]string{}
	}
	l.methods[path] = append(l.methods[path], method)
}

func (l *mockLog) saw(path string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string{}, l.methods[path]...)
}

func (l *mockLog) sawPrefix(prefix string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for p, ms := range l.methods {
		if strings.HasPrefix(p, prefix) {
			n += len(ms)
		}
	}
	return n
}

// labServer: admin confirmed, .git HEAD marker, soft-404 catch-all, negatif temiz.
func labServer(log *mockLog) *httptest.Server {
	catchAll := `<html><body><h1>Oops, page not found (404)</h1><p>Try home.</p></body></html>`
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r.URL.Path, r.Method)
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`<html><body><h1>Admin Dashboard</h1><form><input type="password" name="p"></form></body></html>`))
		case "/old-admin":
			w.Header().Set("Location", "/admin")
			w.WriteHeader(301)
		case "/.git/HEAD":
			if r.Method == http.MethodHead {
				w.Header().Set("Content-Length", "23")
				w.WriteHeader(200)
				return
			}
			w.WriteHeader(200)
			_, _ = w.Write([]byte("ref: refs/heads/main\n"))
		case "/config.php":
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`<?php define('DB_PASSWORD','s3cr3t'); // admin panel config`))
		case "/config.php.bak", "/config.php.old", "/config.php.swp", "/config.php~":
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`<?php define('DB_PASSWORD','s3cr3t'); // backup`))
		case "/bare":
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`<html><body><p>hello world, no signal here</p></body></html>`))
		case "/secret403":
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`forbidden`))
		default:
			// Soft-404 catch-all: GET 200 + sabit gövde (baseline bunu öğrenir).
			// HEAD bilinmeyene 404 (gerçekçi HEAD kontrol negatifi).
			if r.Method == http.MethodHead {
				w.WriteHeader(404)
				return
			}
			w.WriteHeader(200)
			_, _ = w.Write([]byte(catchAll))
		}
	}))
}

func testClient(t *testing.T, srvURL string) *probe.Client {
	t.Helper()
	cfg := plugin.PolicyConfig{
		MaxRequestsPerTarget: 1000,
		MaxRequestsTotal:     10000,
		RatePerSecond:        0, // testte limitsiz
		MaxResponseBytes:     1024 * 1024,
	}
	ps := plugin.NewPolicySession(cfg, nil)
	ps.SetOriginalTarget(srvURL)
	return probe.NewClient(probe.Options{
		Policy:         ps,
		RequestTimeout: 5 * time.Second,
		MaxBytes:       1024 * 1024,
	})
}

func findingsByPath(t *testing.T, res *ContentResult) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, f := range res.Findings {
		if f.RuleID != RuleIDExposedPath {
			t.Fatalf("yanlış rule %s (GASH-028 beklenir)", f.RuleID)
		}
		p := f.Evidence["path"]
		out[p] = string(f.Confidence)
	}
	return out
}

func TestContentDiscoveryConfirmedTentativeReject(t *testing.T) {
	log := &mockLog{}
	srv := labServer(log)
	defer srv.Close()
	client := testClient(t, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	opts := DefaultContentOptions()
	opts.Entries = []string{"admin", "old-admin", ".git/HEAD", "dashboard", "bare", "secret403", "no-such-page-xyz"}
	opts.WordlistName = "test"
	res, err := DiscoverContent(ctx, client, srv.URL, TechFingerprint{}, baseline.NewDefaultModel(), opts)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	got := findingsByPath(t, res)

	if got["/admin"] != "confirmed" {
		t.Errorf("admin 200+keyword confirmed olmalı, got %q (%v)", got["/admin"], got)
	}
	if got["/.git/HEAD"] != "tentative" {
		t.Errorf(".git/HEAD HEAD-only tentative olmalı, got %q", got["/.git/HEAD"])
	}
	if got["/bare"] != "tentative" {
		t.Errorf("çıplak 200 en fazla tentative, got %q", got["/bare"])
	}
	if got["/secret403"] != "tentative" {
		t.Errorf("403 candidate tentative olmalı, got %q", got["/secret403"])
	}
	if got["/old-admin"] != "tentative" {
		t.Errorf("301 candidate tentative olmalı, got %q", got["/old-admin"])
	}
	// Soft-404 catch-all + negatif temiz: dashboard ve no-such-page bulgu ÜRETMEMELİ.
	if _, ok := got["/dashboard"]; ok {
		t.Errorf("catch-all FP: /dashboard bulgu üretmemeli")
	}
	if _, ok := got["/no-such-page-xyz"]; ok {
		t.Errorf("negatif FP: /no-such-page-xyz bulgu üretmemeli")
	}
	// Hassas path gövde çekilmemeli: .git/HEAD yalnızca HEAD ile vurulmalı.
	for _, m := range log.saw("/.git/HEAD") {
		if m != http.MethodHead {
			t.Errorf(".git/HEAD gövde çekilmiş (metot %s) — HEAD-only ihlali", m)
		}
	}
}

func TestContentDiscoverySoft404EchoDowngrade(t *testing.T) {
	// Echo'lu catch-all: path'i gövdeye yansıtır ("Page /admin not found").
	// Baseline hash'i tutmaz ama notfound-ibare indirimi FP'yi frenler.
	log := &mockLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r.URL.Path, r.Method)
		if r.URL.Path == "/admin" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`<html><body><h1>Admin Dashboard</h1><input type="password"></body></html>`))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`<html><body>Page ` + r.URL.Path + ` not found (404). <a href="/admin">admin home</a></body></html>`))
	}))
	defer srv.Close()
	_ = log
	client := testClient(t, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	opts := DefaultContentOptions()
	opts.Entries = []string{"admin", "ghost-page-abc"}
	opts.WordlistName = "test"
	res, err := DiscoverContent(ctx, client, srv.URL, TechFingerprint{}, baseline.NewDefaultModel(), opts)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	got := findingsByPath(t, res)
	if got["/admin"] != "confirmed" {
		t.Errorf("gerçek admin confirmed olmalı, got %q", got["/admin"])
	}
	// ghost-page echo + notfound ibaresi: en fazla tentative (downgrade), tercihen reject değil.
	if c, ok := got["/ghost-page-abc"]; ok && c == "confirmed" {
		t.Errorf("echo catch-all confirmed OLMAMALI (got confirmed)")
	}
}

func TestContentDiscoveryRecurseDepth(t *testing.T) {
	newRes := func(t *testing.T, depth int) (*ContentResult, *mockLog) {
		log := &mockLog{}
		srv := labServer(log)
		t.Cleanup(srv.Close)
		client := testClient(t, srv.URL)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		opts := DefaultContentOptions()
		opts.MaxRecurseDepth = depth
		opts.Entries = []string{"config.php"}
		opts.WordlistName = "test"
		res, err := DiscoverContent(ctx, client, srv.URL, TechFingerprint{}, baseline.NewDefaultModel(), opts)
		if err != nil {
			t.Fatalf("discover: %v", err)
		}
		return res, log
	}

	// Tavan 0: yedek prob YOK.
	res0, log0 := newRes(t, 0)
	got0 := findingsByPath(t, res0)
	if got0["/config.php"] != "confirmed" {
		t.Fatalf("config.php confirmed olmalı, got %q", got0["/config.php"])
	}
	if log0.sawPrefix("/config.php.bak") > 0 || log0.sawPrefix("/config.php.old") > 0 {
		t.Errorf("derinlik 0 iken yedek prob yapılmamalı")
	}

	// Tavan 2: yedek problar VAR + bulgu derinliği ≤2.
	res2, log2 := newRes(t, 2)
	got2 := findingsByPath(t, res2)
	if got2["/config.php.bak"] == "" {
		t.Errorf("smart-recurse /config.php.bak bulmalı (%v)", got2)
	}
	for _, f := range res2.Findings {
		var d int
		_, _ = scanDepth(f.Evidence["depth"], &d)
		if d > 2 {
			t.Errorf("derinlik tavanı aşıldı: %s depth=%d", f.Evidence["path"], d)
		}
	}
	_ = log2
}

func scanDepth(s string, d *int) (int, error) {
	if s == "0" {
		*d = 0
		return 0, nil
	}
	if s == "1" {
		*d = 1
		return 1, nil
	}
	if s == "2" {
		*d = 2
		return 2, nil
	}
	*d = 99
	return 99, nil
}

func TestWordlistTechSelection(t *testing.T) {
	mk := func(tech ...string) TechFingerprint { return TechFingerprint{Tech: tech} }
	cases := []struct {
		fp   TechFingerprint
		name string
		want string // içermesi gereken girdi
	}{
		{mk("wordpress"), "common+wordpress", "wp-login.php"},
		{mk("php"), "common+php", "composer.json"},
		{mk("laravel"), "common+php", "composer.json"},
		{mk("express"), "common+node", "package.json"},
		{mk("nextjs"), "common+node", "package.json"},
		{mk("java"), "common+java", "WEB-INF/web.xml"},
		{mk("django"), "common+python", "requirements.txt"},
		{mk(), "common", "admin"},
		{mk("rails"), "common", "admin"},
	}
	for _, c := range cases {
		name, entries := WordlistForTech(c.fp)
		if name != c.name {
			t.Errorf("tech %v: liste %q, want %q", c.fp.Tech, name, c.name)
		}
		found := false
		for _, e := range entries {
			if e == c.want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("tech %v: %q girdisi yok (%d girdi)", c.fp.Tech, c.want, len(entries))
		}
	}
	// Her pinned liste ≤50 satır.
	for _, n := range WordlistNames() {
		if l := len(wordlistLoad(n)); l == 0 || l > 50 {
			t.Errorf("wordlist %s: %d satır (1..50 olmalı)", n, l)
		}
	}
	// Hassas kapsama: .git/HEAD ve config/admin klasikleri bir listede olmalı.
	_, common := WordlistForTech(TechFingerprint{})
	need := []string{".git/HEAD", "admin", "config.php", "backup.zip"}
	for _, n := range need {
		found := false
		for _, e := range common {
			if e == n {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("common/tech yüzeyinde %q klasiği yok", n)
		}
	}
	if !IsSensitivePath(".git/HEAD") || !IsSensitivePath("/.svn/entries") {
		t.Errorf("hassas path tanınmalı")
	}
	if IsSensitivePath("/admin") {
		t.Errorf("/admin hassas sayılmamalı")
	}
}

// TestContentDiscoveryBudget proves a slow target/proxy cannot keep the
// wordlist phase alive past its time cap.
func TestContentDiscoveryBudget(t *testing.T) {
	old := contentDiscoveryBudget
	contentDiscoveryBudget = 50 * time.Millisecond
	defer func() { contentDiscoveryBudget = old }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(200 * time.Millisecond):
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := testClient(t, srv.URL)
	opts := DefaultContentOptions()
	opts.BaselineSamples = 1
	opts.Entries = []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	start := time.Now()
	res, err := DiscoverContent(context.Background(), client, srv.URL, TechFingerprint{}, baseline.NewDefaultModel(), opts)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("content discovery budget not enforced: %s", elapsed)
	}
	if !res.BudgetExhausted {
		t.Fatalf("budget exhaustion not reported: %+v", res)
	}
}

// TestContentDiscoveryParallelProbes proves the wordlist phase no longer
// issues its bounded probes one at a time.
func TestContentDiscoveryParallelProbes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := testClient(t, srv.URL)
	opts := DefaultContentOptions()
	opts.BaselineSamples = 1
	opts.MaxRecurseDepth = 0
	for i := 0; i < 24; i++ {
		opts.Entries = append(opts.Entries, "probe-"+string(rune('a'+i)))
	}
	start := time.Now()
	res, err := DiscoverContent(context.Background(), client, srv.URL, TechFingerprint{}, baseline.NewDefaultModel(), opts)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("probes look serial: %s for %d requests", elapsed, res.Requests)
	}
	if res.Requests < 24 {
		t.Fatalf("expected at least 24 probes, got %d", res.Requests)
	}
}

// TestContentDiscoveryProgress proves the spinner receives bounded progress.
func TestContentDiscoveryProgress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := testClient(t, srv.URL)
	opts := DefaultContentOptions()
	opts.BaselineSamples = 1
	opts.MaxRecurseDepth = 0
	opts.Entries = []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	var calls, lastDone, lastTotal int
	opts.OnProgress = func(done, total int) {
		calls++
		lastDone, lastTotal = done, total
	}
	res, err := DiscoverContent(context.Background(), client, srv.URL, TechFingerprint{}, baseline.NewDefaultModel(), opts)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if calls < 2 {
		t.Fatalf("progress callback not used: %d calls", calls)
	}
	if lastTotal != opts.MaxProbes || lastDone < res.Requests {
		t.Fatalf("progress = %d/%d, requests=%d", lastDone, lastTotal, res.Requests)
	}
}
