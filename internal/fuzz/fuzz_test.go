// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package fuzz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/probe"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) (*probe.Client, string) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	policy := plugin.NewPolicySession(plugin.PolicyConfig{
		MaxRequestsPerTarget: 10000,
		MaxRequestsTotal:     10000,
		RatePerSecond:        0,
	}, nil)
	return probe.NewClient(probe.Options{Policy: policy}), srv.URL
}

func TestEngineBaselineAndRun(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello world"))
	})

	target := Target{
		Method: http.MethodGet,
		URL:    baseURL + "/search?q=test&page=1",
	}
	budget := Budget{MaxRequests: 50, MinDivergence: 0.05, Profile: ProfileStandard}
	engine := NewEngine(client, Baseline{}, budget, 42)

	err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run hatası: %v", err)
	}
	if engine.Count() == 0 {
		t.Fatal("en az 1 istek yapılmalı")
	}
	if engine.baseline.Response == nil {
		t.Fatal("baseline kaydedilmeli")
	}
}

func TestEngineBudgetLimit(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	target := Target{
		Method: http.MethodGet,
		URL:    baseURL + "/api?a=1&b=2&c=3&d=4&e=5",
	}
	budget := Budget{MaxRequests: 3, MinDivergence: 0.05, Profile: ProfileStandard}
	engine := NewEngine(client, Baseline{}, budget, 42)

	err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run hatası: %v", err)
	}
	if engine.Count() > 3 {
		t.Fatalf("bütçe aşıldı: %d > 3", engine.Count())
	}
}

func TestEngineStopOnDiverge(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") != "test" && r.URL.Query().Get("q") != "" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("error occurred"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("normal"))
	})

	target := Target{
		Method: http.MethodGet,
		URL:    baseURL + "/search?q=test",
	}
	budget := Budget{MaxRequests: 100, MinDivergence: 0.05, StopOnDiverge: true, Profile: ProfileStandard}
	engine := NewEngine(client, Baseline{}, budget, 42)

	err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run hatası: %v", err)
	}
	if !engine.Stopped() {
		t.Fatal("anlamlı farklılıkta durmalı")
	}
	if len(engine.Findings()) == 0 {
		t.Fatal("finding kaydedilmeli")
	}
}

func TestEngineFindingsRecorded(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") != "test" && r.URL.Query().Get("q") != "" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("database error"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("normal response"))
	})

	target := Target{
		Method: http.MethodGet,
		URL:    baseURL + "/search?q=test",
	}
	budget := Budget{MaxRequests: 100, MinDivergence: 0.05, Profile: ProfileStandard}
	engine := NewEngine(client, Baseline{}, budget, 42)

	err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run hatası: %v", err)
	}
	if len(engine.Findings()) == 0 {
		t.Fatal("finding bulunmalı")
	}
	f := engine.Findings()[0]
	if !f.Divergence.Significant {
		t.Fatal("finding significant olmalı")
	}
}

func TestEngineReproducibleSeed(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	target := Target{
		Method: http.MethodGet,
		URL:    baseURL + "/api?x=1&y=2",
	}
	budget := Budget{MaxRequests: 10, MinDivergence: 0.05, Profile: ProfileStandard}

	e1 := NewEngine(client, Baseline{}, budget, 42)
	e2 := NewEngine(client, Baseline{}, budget, 42)

	m1 := e1.generateMutations(target)
	m2 := e2.generateMutations(target)

	if len(m1) != len(m2) {
		t.Fatalf("mutasyon sayıları eşit olmalı: %d vs %d", len(m1), len(m2))
	}
	for i := range m1 {
		if m1[i].Kind != m2[i].Kind {
			t.Fatalf("mutasyon türü eşit olmalı: %s vs %s", m1[i].Kind, m2[i].Kind)
		}
	}
}

func TestEngineProfileBudgets(t *testing.T) {
	b := DefaultBudget(ProfileSafe)
	if b.MaxRequests != 100 {
		t.Fatalf("safe bütçe 100 olmalı: %d", b.MaxRequests)
	}
	b = DefaultBudget(ProfileStandard)
	if b.MaxRequests != 500 {
		t.Fatalf("standard bütçe 500 olmalı: %d", b.MaxRequests)
	}
	b = DefaultBudget(ProfileDeep)
	if b.MaxRequests != 2000 {
		t.Fatalf("deep bütçe 2000 olmalı: %d", b.MaxRequests)
	}
}

func TestEngineDurationLimit(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	target := Target{
		Method: http.MethodGet,
		URL:    baseURL + "/api?a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8",
	}
	budget := Budget{MaxRequests: 1000, MaxDuration: 1 * time.Millisecond, MinDivergence: 0.05, Profile: ProfileStandard}
	engine := NewEngine(client, Baseline{}, budget, 42)

	err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run hatası: %v", err)
	}
	if engine.Count() > 100 {
		t.Fatalf("süre limiti çalışmadı: %d istek", engine.Count())
	}
}

func TestSimilarity(t *testing.T) {
	if similarity([]byte(""), []byte("")) != 1.0 {
		t.Fatal("iki boş body aynı")
	}
	if similarity([]byte("a"), []byte("")) != 0.0 {
		t.Fatal("biri boşsa farklı")
	}
	s := similarity([]byte("hello world"), []byte("hello world"))
	if s != 1.0 {
		t.Fatal("aynı body benzerliği 1.0 olmalı")
	}
	s = similarity([]byte("a b c"), []byte("a b d"))
	if s <= 0 || s >= 1.0 {
		t.Fatalf("kısmi benzerlik 0-1 arası olmalı: %f", s)
	}
}

func TestHashBody(t *testing.T) {
	h1 := hashBody([]byte("test"))
	h2 := hashBody([]byte("test"))
	h3 := hashBody([]byte("other"))
	if h1 != h2 {
		t.Fatal("aynı body aynı hash")
	}
	if h1 == h3 {
		t.Fatal("farklı body farklı hash")
	}
}

func TestApplyMutationURLParam(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	engine := NewEngine(client, Baseline{}, Budget{MaxRequests: 10}, 42)

	target := Target{
		Method: http.MethodGet,
		URL:    baseURL + "/search?q=test&page=1",
	}
	mut := Mutation{Kind: "url_param", Index: 0, Payload: "admin"}
	out, err := engine.applyMutation(target, mut)
	if err != nil {
		t.Fatal(err)
	}
	if out.URL == target.URL {
		t.Fatal("URL param mutasyonu uygulanmalı")
	}
}

func TestApplyMutationHeader(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	engine := NewEngine(client, Baseline{}, Budget{MaxRequests: 10}, 42)

	target := Target{
		Method: http.MethodGet,
		URL:    "http://example.com/api",
	}
	mut := Mutation{Kind: "header", Index: 0, Payload: "127.0.0.1"}
	out, err := engine.applyMutation(target, mut)
	if err != nil {
		t.Fatal(err)
	}
	if out.Headers["X-Fuzz-0"] != "127.0.0.1" {
		t.Fatal("header mutasyonu uygulanmalı")
	}
}

func TestApplyMutationContentType(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	engine := NewEngine(client, Baseline{}, Budget{MaxRequests: 10}, 42)

	target := Target{
		Method: http.MethodPost,
		URL:    "http://example.com/api",
		Body:   []byte(`{"key":"value"}`),
	}
	mut := Mutation{Kind: "content_type", Index: 0, Payload: "application/json"}
	out, err := engine.applyMutation(target, mut)
	if err != nil {
		t.Fatal(err)
	}
	if out.Headers["Content-Type"] != "application/json" {
		t.Fatal("content-type mutasyonu uygulanmalı")
	}
}

func TestEngineDivergenceComparison(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	base := Baseline{
		Response: &probe.Response{Status: 200, Body: []byte("ok")},
		BodyHash: hashBody([]byte("ok")),
	}
	engine := NewEngine(client, base, Budget{MinDivergence: 0.05}, 42)

	resp := &probe.Response{Status: 200, Body: []byte("ok")}
	div := engine.compare(resp)
	if div.Significant {
		t.Fatal("aynı yanıt significant olmamalı")
	}

	resp2 := &probe.Response{Status: 500, Body: []byte("ok")}
	div2 := engine.compare(resp2)
	if !div2.Significant {
		t.Fatal("status farkı significant olmalı")
	}

	resp3 := &probe.Response{Status: 200, Body: []byte("completely different content here")}
	div3 := engine.compare(resp3)
	if !div3.Significant {
		t.Fatal("body farkı significant olmalı")
	}
}

func TestEngineMutationCoverage(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	target := Target{
		Method:  http.MethodPost,
		URL:     baseURL + "/api?a=1",
		Headers: map[string]string{"Accept": "application/json"},
		Cookies: map[string]string{"session": "abc"},
		Body:    []byte(`{"key":"value"}`),
		Profile: ProfileDeep,
	}
	engine := NewEngine(client, Baseline{}, Budget{MaxRequests: 1000, Profile: ProfileDeep}, 42)
	muts := engine.generateMutations(target)

	kinds := make(map[string]bool)
	for _, m := range muts {
		kinds[m.Kind] = true
	}

	expected := []string{"url_param", "json_nested", "header", "cookie", "content_type"}
	for _, e := range expected {
		if !kinds[e] {
			t.Errorf("mutasyon türü eksik: %s", e)
		}
	}
}

func TestSnippet(t *testing.T) {
	s := snippet([]byte("short"), 10)
	if s != "short" {
		t.Fatal("kısa snippet normal olmalı")
	}
	s = snippet([]byte("this is a very long body content"), 10)
	if len(s) != 10 {
		t.Fatalf("snippet 10 karakter olmalı: %d", len(s))
	}
}

func TestFuzzValueCoverage(t *testing.T) {
	kinds := []string{"param", "form", "json", "header", "cookie"}
	for _, k := range kinds {
		v := fuzzValue(k, 0)
		if v == "" {
			t.Fatalf("fuzzValue(%s) boş döndü", k)
		}
	}
	v1 := fuzzValue("param", 0)
	v2 := fuzzValue("param", 1)
	if v1 == v2 {
		t.Fatal("farklı indeksler farklı değer üretmeli")
	}
}

func TestCloneHeaders(t *testing.T) {
	src := map[string]string{"a": "1"}
	dst := cloneHeaders(src)
	dst["a"] = "2"
	if src["a"] != "1" {
		t.Fatal("cloneHeaders deep copy yapmalı")
	}
	if cloneHeaders(nil) != nil {
		t.Fatal("nil map nil döndürmeli")
	}
}

func TestEngineContextCancellation(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	target := Target{
		Method: http.MethodGet,
		URL:    baseURL + "/api?a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8&i=9&j=10",
	}
	budget := Budget{MaxRequests: 100, MinDivergence: 0.05, Profile: ProfileStandard}
	engine := NewEngine(client, Baseline{}, budget, 42)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := engine.Run(ctx, target)
	if err != nil {
		t.Fatalf("Run hatası: %v", err)
	}
	if engine.Count() >= 100 {
		t.Fatal("context cancellation motoru durdurmalı")
	}
}

func TestEngineFindingBodySnippet(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") != "test" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("error detail " + string(make([]byte, 500))))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	target := Target{
		Method: http.MethodGet,
		URL:    baseURL + "/search?q=test",
	}
	budget := Budget{MaxRequests: 50, MinDivergence: 0.05, Profile: ProfileStandard}
	engine := NewEngine(client, Baseline{}, budget, 42)

	err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run hatası: %v", err)
	}

	for _, f := range engine.Findings() {
		if len(f.BodySnippet) > 200 {
			t.Fatalf("snippet 200 karakterden fazla olmamalı: %d", len(f.BodySnippet))
		}
	}
}

func TestEngineSeedVariations(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	target := Target{
		Method: http.MethodGet,
		URL:    baseURL + "/api?x=1&y=2",
	}

	e1 := NewEngine(client, Baseline{}, Budget{MaxRequests: 10}, 123)
	e2 := NewEngine(client, Baseline{}, Budget{MaxRequests: 10}, 123)

	m1 := e1.generateMutations(target)
	m2 := e2.generateMutations(target)

	if len(m1) != len(m2) {
		t.Fatalf("aynı seed aynı mutasyon sayısı üretmeli: %d vs %d", len(m1), len(m2))
	}

	e3 := NewEngine(client, Baseline{}, Budget{MaxRequests: 10}, 456)
	m3 := e3.generateMutations(target)
	if len(m1) != len(m3) {
		t.Fatalf("farklı seed de aynı sayıda mutasyon üretmeli: %d vs %d", len(m1), len(m3))
	}
}

func TestEngineURLParamMutationEncodes(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	engine := NewEngine(client, Baseline{}, Budget{MaxRequests: 10}, 42)

	target := Target{
		Method: http.MethodGet,
		URL:    baseURL + "/search?q=test",
	}
	mut := Mutation{Kind: "url_param", Index: 0, Payload: "<script>alert(1)</script>"}
	out, err := engine.applyMutation(target, mut)
	if err != nil {
		t.Fatal(err)
	}
	if out.URL == target.URL {
		t.Fatal("mutasyon uygulanmalı")
	}
	if !strings.Contains(out.URL, "q=") {
		t.Fatal("q parametresi encoding sonrası da bulunmalı")
	}
}

func TestEngineFormMutationWithBody(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	engine := NewEngine(client, Baseline{}, Budget{MaxRequests: 10}, 42)

	target := Target{
		Method: http.MethodPost,
		URL:    baseURL + "/submit",
		Body:   []byte("field=value"),
	}
	mut := Mutation{Kind: "form_field", Index: 0, Payload: "' OR 1=1--"}
	out, err := engine.applyMutation(target, mut)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Body) == 0 {
		t.Fatal("form mutasyonu body boş olmamalı")
	}
	if string(out.Body) == "field=value" {
		t.Fatal("form mutasyonu body değiştirmeli")
	}
}

func TestEngineJSONNestedMutation(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	engine := NewEngine(client, Baseline{}, Budget{MaxRequests: 10}, 42)

	target := Target{
		Method: http.MethodPost,
		URL:    baseURL + "/api",
		Body:   []byte(`{"key":"value"}`),
	}
	mut := Mutation{Kind: "json_nested", Index: 0, Payload: "admin"}
	out, err := engine.applyMutation(target, mut)
	if err != nil {
		t.Fatal(err)
	}
	bodyStr := string(out.Body)
	if !strings.Contains(bodyStr, `"0"`) {
		t.Fatalf("json nested mutasyonu anahtar eklemeli: %s", bodyStr)
	}
}

func TestEngineHeaderMutationOnExisting(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	engine := NewEngine(client, Baseline{}, Budget{MaxRequests: 10}, 42)

	target := Target{
		Method:  http.MethodGet,
		URL:     baseURL + "/api",
		Headers: map[string]string{"Accept": "text/html"},
	}
	mut := Mutation{Kind: "header", Index: 2, Payload: "true"}
	out, err := engine.applyMutation(target, mut)
	if err != nil {
		t.Fatal(err)
	}
	if out.Headers["Accept"] != "text/html" {
		t.Fatal("mevcut header korunmalı")
	}
	if out.Headers["X-Fuzz-2"] != "true" {
		t.Fatal("yeni header eklenmeli")
	}
}

func TestEngineCookieMutation(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	engine := NewEngine(client, Baseline{}, Budget{MaxRequests: 10}, 42)

	target := Target{
		Method: http.MethodGet,
		URL:    baseURL + "/api",
	}
	mut := Mutation{Kind: "cookie", Index: 0, Payload: "admin"}
	out, err := engine.applyMutation(target, mut)
	if err != nil {
		t.Fatal(err)
	}
	if out.Cookies["fuzz_0"] != "admin" {
		t.Fatal("cookie mutasyonu eklenmeli")
	}
}

func TestEngineMultipleContentTypeMutations(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	engine := NewEngine(client, Baseline{}, Budget{MaxRequests: 100}, 42)

	target := Target{
		Method:  http.MethodPost,
		URL:     baseURL + "/api",
		Body:    []byte(`{}`),
		Profile: ProfileDeep,
	}
	muts := engine.generateMutations(target)

	ctCount := 0
	for _, m := range muts {
		if m.Kind == "content_type" {
			ctCount++
		}
	}
	if ctCount < 3 {
		t.Fatalf("en az 3 content-type mutasyonu olmalı: %d", ctCount)
	}
}

func TestEngineURLParamMutationAllParams(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	engine := NewEngine(client, Baseline{}, Budget{MaxRequests: 100}, 42)

	target := Target{
		Method:  http.MethodGet,
		URL:     baseURL + "/api?a=1&b=2&c=3",
		Profile: ProfileStandard,
	}
	muts := engine.generateMutations(target)

	paramCount := 0
	for _, m := range muts {
		if m.Kind == "url_param" {
			paramCount++
		}
	}
	if paramCount != 3 {
		t.Fatalf("3 url param mutasyonu olmalı: %d", paramCount)
	}
}

func TestEngineEmptyTarget(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	target := Target{
		Method: http.MethodGet,
		URL:    "",
	}
	budget := Budget{MaxRequests: 10, MinDivergence: 0.05}
	engine := NewEngine(client, Baseline{}, budget, 42)

	err := engine.Run(context.Background(), target)
	if err == nil {
		t.Fatal("boş URL hata vermeli")
	}
}

func TestEngineMaxDurationZeroMeansUnlimited(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	target := Target{
		Method: http.MethodGet,
		URL:    baseURL + "/api?a=1&b=2",
	}
	budget := Budget{MaxRequests: 100, MaxDuration: 0, MinDivergence: 0.05}
	engine := NewEngine(client, Baseline{}, budget, 42)

	err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run hatası: %v", err)
	}
	if engine.Count() == 0 {
		t.Fatal("istek yapılmalı")
	}
}

func TestEngineDivergenceStatusOnly(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	base := Baseline{
		Response: &probe.Response{Status: 200, Body: []byte("ok")},
		BodyHash: hashBody([]byte("ok")),
	}
	engine := NewEngine(client, base, Budget{MinDivergence: 0.05}, 42)

	resp := &probe.Response{Status: 302, Body: []byte("ok")}
	div := engine.compare(resp)
	if !div.StatusDiff {
		t.Fatal("status farkı işaretlenmeli")
	}
	if !div.Significant {
		t.Fatal("status farkı significant olmalı")
	}
}

func TestEngineDivergenceLengthOnly(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	base := Baseline{
		Response: &probe.Response{Status: 200, Body: []byte("ok")},
		BodyHash: hashBody([]byte("ok")),
	}
	engine := NewEngine(client, base, Budget{MinDivergence: 0.05}, 42)

	longBody := make([]byte, 10000)
	for i := range longBody {
		longBody[i] = 'x'
	}
	resp := &probe.Response{Status: 200, Body: longBody}
	div := engine.compare(resp)
	if !div.LengthDiff {
		t.Fatal("length farkı işaretlenmeli")
	}
}

func TestEngineDivergenceTimingOnly(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	base := Baseline{
		Response: &probe.Response{Status: 200, Body: []byte("ok"), RTT: 10 * time.Millisecond},
		BodyHash: hashBody([]byte("ok")),
	}
	engine := NewEngine(client, base, Budget{MinDivergence: 0.05}, 42)

	resp := &probe.Response{Status: 200, Body: []byte("ok"), RTT: 1 * time.Second}
	div := engine.compare(resp)
	if !div.TimingDiff {
		t.Fatal("timing farkı işaretlenmeli")
	}
}

func TestEngineDivergenceSimilarBodyNotSignificant(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	base := Baseline{
		Response: &probe.Response{Status: 200, Body: []byte("hello world test")},
		BodyHash: hashBody([]byte("hello world test")),
	}
	engine := NewEngine(client, base, Budget{MinDivergence: 0.05}, 42)

	resp := &probe.Response{Status: 200, Body: []byte("hello world test")}
	div := engine.compare(resp)
	if div.Significant {
		t.Fatal("aynı body significant olmamalı")
	}
}

func TestEngineFindingsOrderPreserved(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		switch q {
		case "test":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		case "'":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("db error"))
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("bad request"))
		}
	})

	target := Target{
		Method: http.MethodGet,
		URL:    baseURL + "/search?q=test",
	}
	budget := Budget{MaxRequests: 100, MinDivergence: 0.02, Profile: ProfileStandard}
	engine := NewEngine(client, Baseline{}, budget, 42)

	err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run hatası: %v", err)
	}

	findings := engine.Findings()
	if len(findings) == 0 {
		t.Fatal("finding bulunmalı")
	}
	for i := 1; i < len(findings); i++ {
		if findings[i].Mutation.Kind == "" {
			t.Fatalf("finding %d mutasyon türü boş", i)
		}
	}
}

func TestEngineBudgetNotExceededWithManyMutations(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	target := Target{
		Method:  http.MethodPost,
		URL:     baseURL + "/api?a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8",
		Headers: map[string]string{"Accept": "application/json", "X-Custom": "val"},
		Cookies: map[string]string{"s1": "v1", "s2": "v2", "s3": "v3"},
		Body:    []byte(`{"k":"v"}`),
		Profile: ProfileDeep,
	}
	budget := Budget{MaxRequests: 10, MinDivergence: 0.05, Profile: ProfileDeep}
	engine := NewEngine(client, Baseline{}, budget, 42)

	err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run hatası: %v", err)
	}
	if engine.Count() > 10 {
		t.Fatalf("bütçe aşıldı: %d > 10", engine.Count())
	}
}

func TestEngineTargetMethodPreserved(t *testing.T) {
	var capturedMethod string
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	target := Target{
		Method: http.MethodPost,
		URL:    baseURL + "/api?a=1",
	}
	budget := Budget{MaxRequests: 5, MinDivergence: 0.05}
	engine := NewEngine(client, Baseline{}, budget, 42)

	_ = engine.Run(context.Background(), target)
	if capturedMethod != http.MethodPost {
		t.Fatalf("method POST olmalı: %s", capturedMethod)
	}
}

func TestEngineTargetCookiesPreserved(t *testing.T) {
	var capturedCookies string
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		capturedCookies = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	target := Target{
		Method:  http.MethodGet,
		URL:     baseURL + "/api",
		Cookies: map[string]string{"session": "abc123"},
	}
	budget := Budget{MaxRequests: 5, MinDivergence: 0.05}
	engine := NewEngine(client, Baseline{}, budget, 42)

	_ = engine.Run(context.Background(), target)
	if capturedCookies == "" {
		t.Fatal("cookie header gönderilmeli")
	}
}

func TestEngineTargetHeadersPreserved(t *testing.T) {
	var capturedAccept string
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		capturedAccept = r.Header.Get("Accept")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	target := Target{
		Method:  http.MethodGet,
		URL:     baseURL + "/api",
		Headers: map[string]string{"Accept": "application/json"},
	}
	budget := Budget{MaxRequests: 5, MinDivergence: 0.05}
	engine := NewEngine(client, Baseline{}, budget, 42)

	_ = engine.Run(context.Background(), target)
	if capturedAccept != "application/json" {
		t.Fatal("Accept header korunmalı")
	}
}

func TestEngineFormMutationWithoutBody(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	engine := NewEngine(client, Baseline{}, Budget{MaxRequests: 10}, 42)

	target := Target{
		Method: http.MethodGet,
		URL:    baseURL + "/api",
	}
	mut := Mutation{Kind: "form_field", Index: 0, Payload: "x"}
	out, err := engine.applyMutation(target, mut)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Body) != 0 {
		t.Fatal("body yoksa form mutasyonu body oluşturmamalı")
	}
}

func TestEngineJSONMutationWithoutBody(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	engine := NewEngine(client, Baseline{}, Budget{MaxRequests: 10}, 42)

	target := Target{
		Method: http.MethodGet,
		URL:    baseURL + "/api",
	}
	mut := Mutation{Kind: "json_nested", Index: 0, Payload: "x"}
	out, err := engine.applyMutation(target, mut)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Body) != 0 {
		t.Fatal("body yoksa json mutasyonu body oluşturmamalı")
	}
}

func TestEngineURLParamMutationInvalidURL(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	engine := NewEngine(client, Baseline{}, Budget{MaxRequests: 10}, 42)

	target := Target{
		Method: http.MethodGet,
		URL:    "://invalid-url",
	}
	mut := Mutation{Kind: "url_param", Index: 0, Payload: "x"}
	_, err := engine.applyMutation(target, mut)
	if err == nil {
		t.Fatal("geçersiz URL hata vermeli")
	}
}

func TestEngineURLParamMutationIndexOutOfRange(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	engine := NewEngine(client, Baseline{}, Budget{MaxRequests: 10}, 42)

	target := Target{
		Method: http.MethodGet,
		URL:    baseURL + "/api?only=1",
	}
	mut := Mutation{Kind: "url_param", Index: 5, Payload: "x"}
	out, err := engine.applyMutation(target, mut)
	if err != nil {
		t.Fatal(err)
	}
	if out.URL != target.URL {
		t.Fatal("index dışında değişiklik olmamalı")
	}
}

func TestEngineGenerateMutationsEmptyURL(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	engine := NewEngine(client, Baseline{}, Budget{MaxRequests: 10}, 42)

	target := Target{
		Method: http.MethodGet,
		URL:    "",
	}
	muts := engine.generateMutations(target)
	for _, m := range muts {
		if m.Kind == "url_param" {
			t.Fatal("boş URL'de url_param mutasyonu olmamalı")
		}
	}
}

func TestEngineRunWithPreExistingBaseline(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	target := Target{
		Method: http.MethodGet,
		URL:    baseURL + "/api?a=1&b=2",
	}

	base := Baseline{
		Response: &probe.Response{Status: 200, Body: []byte("ok")},
		BodyHash: hashBody([]byte("ok")),
	}
	budget := Budget{MaxRequests: 50, MinDivergence: 0.05}
	engine := NewEngine(client, base, budget, 42)

	err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run hatası: %v", err)
	}
	if engine.Count() == 0 {
		t.Fatal("mutasyon istekleri yapılmalı")
	}
}

func TestEngineFindingsThreadSafe(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	budget := Budget{MaxRequests: 1000, MinDivergence: 0.05, Profile: ProfileDeep}
	engine := NewEngine(client, Baseline{}, budget, 42)

	done := make(chan bool)
	go func() {
		_ = engine.Findings()
		done <- true
	}()
	go func() {
		_ = engine.Count()
		done <- true
	}()
	<-done
	<-done
	_ = baseURL
}

func TestEngineProfileSafeNoHeaderMutations(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	engine := NewEngine(client, Baseline{}, Budget{MaxRequests: 100, Profile: ProfileSafe}, 42)

	target := Target{
		Method:  http.MethodGet,
		URL:     baseURL + "/api?a=1&b=2",
		Headers: map[string]string{"Accept": "text/html"},
		Cookies: map[string]string{"s": "v"},
		Profile: ProfileSafe,
	}
	muts := engine.generateMutations(target)

	for _, m := range muts {
		if m.Kind == "header" || m.Kind == "cookie" || m.Kind == "content_type" {
			t.Fatalf("safe profilinde %s mutasyonu olmamalı", m.Kind)
		}
	}
}

func TestEngineProfileStandardHasHeaderNoCookie(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	engine := NewEngine(client, Baseline{}, Budget{MaxRequests: 100, Profile: ProfileStandard}, 42)

	target := Target{
		Method:  http.MethodGet,
		URL:     baseURL + "/api?a=1",
		Headers: map[string]string{"Accept": "text/html"},
		Profile: ProfileStandard,
	}
	muts := engine.generateMutations(target)

	hasHeader := false
	hasCookie := false
	for _, m := range muts {
		if m.Kind == "header" {
			hasHeader = true
		}
		if m.Kind == "cookie" {
			hasCookie = true
		}
	}
	if !hasHeader {
		t.Fatal("standard profilinde header mutasyonu olmalı")
	}
	if hasCookie {
		t.Fatal("standard profilinde cookie mutasyonu olmamalı")
	}
}

func TestEngineBudgetStopOnDivergeDisabled(t *testing.T) {
	client, baseURL := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("a") == "1" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("error"))
		}
	})

	target := Target{
		Method: http.MethodGet,
		URL:    baseURL + "/api?a=1&b=2&c=3&d=4&e=5",
	}
	budget := Budget{MaxRequests: 100, MinDivergence: 0.05, StopOnDiverge: false, Profile: ProfileStandard}
	engine := NewEngine(client, Baseline{}, budget, 42)

	err := engine.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("Run hatası: %v", err)
	}
	if engine.Stopped() {
		t.Fatal("StopOnDiverge=false iken motor durmamalı")
	}
	if engine.Count() < 5 {
		t.Fatalf("tüm mutasyonlar denenmeli: %d istek", engine.Count())
	}
}
