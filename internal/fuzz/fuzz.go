// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package fuzz kontrollü mutasyon motoru + baseline karşılaştırma + bütçeli üretim.
// Mevcut probe.Client ve PolicySession üzerinde çalışır; yeni HTTP client YOK.
package fuzz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/probe"
)

// Target fuzz hedefi: bir HTTP iskeleti + mutasyon noktaları.
type Target struct {
	Method  string
	URL     string
	Headers map[string]string
	Cookies map[string]string
	Body    []byte
	// Profile davranışı: GET-only veya tüm methodlar
	Profile Profile
}

// Profile fuzz bütçesi davranışı.
type Profile int

const (
	// ProfileSafe yalnızca GET/HEAD, düşük bütçe.
	ProfileSafe Profile = iota
	// ProfileStandard GET/POST + param, orta bütçe.
	ProfileStandard
	// ProfileDeep tüm method + header/cookie, yüksek bütçe.
	ProfileDeep
)

// Mutation tek bir mutasyon işlemi.
type Mutation struct {
	Seed    int64
	Kind    string // "url_param", "form_field", "json_nested", "header", "cookie", "content_type"
	Index   int
	Payload string
}

// Budget istek bütçesi + durdurma politikası.
type Budget struct {
	MaxRequests   int64
	MaxDuration   time.Duration
	StopOnDiverge bool    // anlamlı farklılık bulununca dur
	MinDivergence float64 // gürültü eşiği (0.0-1.0, body benzerliği)
	Profile       Profile
}

// DefaultBudget profil için varsayılan bütçe.
func DefaultBudget(p Profile) Budget {
	switch p {
	case ProfileSafe:
		return Budget{MaxRequests: 100, Profile: p, MinDivergence: 0.05}
	case ProfileStandard:
		return Budget{MaxRequests: 500, Profile: p, MinDivergence: 0.03}
	case ProfileDeep:
		return Budget{MaxRequests: 2000, Profile: p, MinDivergence: 0.02}
	default:
		return Budget{MaxRequests: 100, Profile: ProfileSafe, MinDivergence: 0.05}
	}
}

// Divergence yanıt farklılık analizi.
type Divergence struct {
	StatusDiff  bool
	LengthDiff  bool
	TimingDiff  bool
	BodyDiff    bool
	BodyHash    string
	SimScore    float64 // 0.0 = tamamen farklı, 1.0 = aynı
	Significant bool    // eşik üzerinde mi
}

// Baseline referans yanıt.
type Baseline struct {
	Target    Target
	Response  *probe.Response
	BodyHash  string
	Timestamp time.Time
}

// Engine kontrollü mutasyon motoru.
type Engine struct {
	client   *probe.Client
	baseline Baseline
	budget   Budget
	rng      *rand.Rand
	mu       sync.Mutex
	count    atomic.Int64
	stopped  atomic.Bool
	findings []Finding
}

// Finding anlamlı farklılık kaydı.
type Finding struct {
	Mutation    Mutation
	Divergence  Divergence
	RespStatus  int
	BodySnippet string
	// BodyExcerpt oracle sınıflandırması için 4KB alıntıdır (imza kesilmez).
	BodyExcerpt string
}

// NewEngine motor kurar; baseline nil ise ilk istek baseline olur.
// seed 0 ise zaman bazlı üretim yapılır.
func NewEngine(client *probe.Client, baseline Baseline, budget Budget, seed int64) *Engine {
	src := seed
	if src == 0 {
		src = time.Now().UnixNano()
	}
	return &Engine{
		client:   client,
		baseline: baseline,
		budget:   budget,
		rng:      rand.New(rand.NewSource(src)),
	}
}

// NewBaseline hazır bir kontrol yanıtından baseline kurar.
// What: runActiveFuzz gibi dış çağıranlar kontrol isteğini kendisi atar;
// motor iç baseline isteğini atlar (tekrar istek YOK).
// Why: Kontrol gövdesi oracle karşılaştırmasında da kullanılır.
func NewBaseline(target Target, resp *probe.Response) Baseline {
	return Baseline{
		Target:    target,
		Response:  resp,
		BodyHash:  hashBody(resp.Body),
		Timestamp: time.Now(),
	}
}

// Count yapılan istek sayısı.
func (e *Engine) Count() int64 { return e.count.Load() }

// Stopped motor durdu mu.
func (e *Engine) Stopped() bool { return e.stopped.Load() }

// Findings bulunan farklılıklar.
func (e *Engine) Findings() []Finding {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Finding, len(e.findings))
	copy(out, e.findings)
	return out
}

// Run mutasyon döngüsü: bütçe/durdurma politikasıyla tekrarlanabilir seed.
func (e *Engine) Run(ctx context.Context, target Target) error {
	// Baseline yoksa ilk istek baseline olarak kaydedilir.
	if e.baseline.Response == nil {
		resp, err := e.sendRaw(ctx, target)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("baseline request: %w", err)
		}
		e.baseline = Baseline{
			Target:    target,
			Response:  resp,
			BodyHash:  hashBody(resp.Body),
			Timestamp: time.Now(),
		}
	}

	mutations := e.generateMutations(target)
	for _, mut := range mutations {
		if e.budget.StopOnDiverge && e.stopped.Load() {
			return nil
		}
		if e.count.Load() >= e.budget.MaxRequests {
			return nil
		}
		if e.budget.MaxDuration > 0 && time.Since(e.baseline.Timestamp) > e.budget.MaxDuration {
			return nil
		}

		mutated, err := e.applyMutation(target, mut)
		if err != nil {
			continue
		}

		resp, err := e.sendRaw(ctx, mutated)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			e.count.Add(1)
			continue
		}
		e.count.Add(1)

		div := e.compare(resp)
		if div.Significant {
			e.mu.Lock()
			e.findings = append(e.findings, Finding{
				Mutation:    mut,
				Divergence:  div,
				RespStatus:  resp.Status,
				BodySnippet: snippet(resp.Body, 200),
				// 4KB alıntı: SQL imza/oracle sınıflandırması kesilmeden yapılır.
				BodyExcerpt: snippet(resp.Body, 4096),
			})
			e.mu.Unlock()
			if e.budget.StopOnDiverge {
				e.stopped.Store(true)
				return nil
			}
		}
	}
	return nil
}

// applyMutation hedefe mutasyon uygular.
func (e *Engine) applyMutation(t Target, m Mutation) (Target, error) {
	out := Target{
		Method:  t.Method,
		URL:     t.URL,
		Headers: cloneHeaders(t.Headers),
		Cookies: cloneHeaders(t.Cookies),
		Body:    append([]byte(nil), t.Body...),
		Profile: t.Profile,
	}

	u, err := url.Parse(out.URL)
	if err != nil {
		return out, err
	}

	switch m.Kind {
	case "url_param":
		q := u.Query()
		if m.Index < len(q) {
			keys := make([]string, 0, len(q))
			for k := range q {
				keys = append(keys, k)
			}
			if m.Index < len(keys) {
				key := keys[m.Index]
				q.Set(key, m.Payload)
				u.RawQuery = q.Encode()
				out.URL = u.String()
			}
		}
	case "form_field":
		if len(out.Body) > 0 {
			bodyStr := string(out.Body)
			bodyStr = strings.Replace(bodyStr, "=", "="+m.Payload, 1)
			out.Body = []byte(bodyStr)
		}
	case "json_nested":
		if len(out.Body) > 0 {
			bodyStr := string(out.Body)
			bodyStr = strings.Replace(bodyStr, "{", `{"`+fmt.Sprint(m.Index)+`":"`+m.Payload+`",`, 1)
			out.Body = []byte(bodyStr)
		}
	case "header":
		if out.Headers == nil {
			out.Headers = make(map[string]string)
		}
		out.Headers["X-Fuzz-"+fmt.Sprint(m.Index)] = m.Payload
	case "cookie":
		if out.Cookies == nil {
			out.Cookies = make(map[string]string)
		}
		out.Cookies["fuzz_"+fmt.Sprint(m.Index)] = m.Payload
	case "content_type":
		if out.Headers == nil {
			out.Headers = make(map[string]string)
		}
		out.Headers["Content-Type"] = m.Payload
	}
	return out, nil
}

// generateMutations hedef için mutasyon listesi üretir.
func (e *Engine) generateMutations(t Target) []Mutation {
	var mutations []Mutation
	seed := e.rng.Int63()

	// URL param mutasyonları
	u, err := url.Parse(t.URL)
	if err == nil {
		q := u.Query()
		idx := 0
		for key := range q {
			_ = key
			mutations = append(mutations, Mutation{
				Seed:    seed,
				Kind:    "url_param",
				Index:   idx,
				Payload: fuzzValue("param", idx),
			})
			idx++
		}
	}

	// Form field mutasyonu (body varsa)
	if len(t.Body) > 0 {
		mutations = append(mutations, Mutation{
			Seed:    seed,
			Kind:    "form_field",
			Index:   0,
			Payload: fuzzValue("form", 0),
		})
	}

	// JSON nested mutasyonu
	if len(t.Body) > 0 {
		mutations = append(mutations, Mutation{
			Seed:    seed,
			Kind:    "json_nested",
			Index:   0,
			Payload: fuzzValue("json", 0),
		})
	}

	// Header mutasyonları
	if t.Profile >= ProfileStandard {
		headerNames := []string{"X-Custom", "X-Forwarded-For", "Authorization", "Accept"}
		for i, h := range headerNames {
			mutations = append(mutations, Mutation{
				Seed:    seed,
				Kind:    "header",
				Index:   i,
				Payload: fuzzValue("header", i),
			})
			_ = h
		}
	}

	// Cookie mutasyonları
	if t.Profile >= ProfileDeep {
		cookieNames := []string{"sessionid", "token", "auth", "csrf"}
		for i, c := range cookieNames {
			mutations = append(mutations, Mutation{
				Seed:    seed,
				Kind:    "cookie",
				Index:   i,
				Payload: fuzzValue("cookie", i),
			})
			_ = c
		}
	}

	// Content-type mutasyonları
	if t.Profile >= ProfileDeep {
		ctypes := []string{"application/x-www-form-urlencoded", "application/json", "text/xml", "multipart/form-data"}
		for i, ct := range ctypes {
			mutations = append(mutations, Mutation{
				Seed:    seed,
				Kind:    "content_type",
				Index:   i,
				Payload: ct,
			})
		}
	}

	return mutations
}

// sendRaw probe.Client ile istek gönderir (PolicySession üzerinden).
func (e *Engine) sendRaw(ctx context.Context, t Target) (*probe.Response, error) {
	headers := make(map[string]string)
	for k, v := range t.Headers {
		headers[k] = v
	}
	// Cookie header'a ekle
	if len(t.Cookies) > 0 {
		var cookieParts []string
		for k, v := range t.Cookies {
			cookieParts = append(cookieParts, k+"="+v)
		}
		headers["Cookie"] = strings.Join(cookieParts, "; ")
	}

	// ctx'ye plugin safe bilgisi ekle (GET için safe)
	method := t.Method
	if method == "" {
		method = http.MethodGet
	}
	pctx := plugin.WithPlugin(ctx, "fuzz", method == http.MethodGet || method == http.MethodHead, nil)

	return e.client.Send(pctx, method, t.URL, headers, t.Body)
}

// compare yanıtı baseline ile karşılaştırır.
func (e *Engine) compare(resp *probe.Response) Divergence {
	base := e.baseline.Response
	if base == nil {
		return Divergence{}
	}

	hash := hashBody(resp.Body)
	statusDiff := resp.Status != base.Status
	lengthDiff := abs(len(resp.Body)-len(base.Body)) > 10
	timingDiff := resp.RTT > base.RTT*2 && resp.RTT-base.RTT > 500*time.Millisecond
	bodyDiff := hash != e.baseline.BodyHash

	sim := similarity(base.Body, resp.Body)
	sig := statusDiff || timingDiff || (bodyDiff && sim < 1.0-e.budget.MinDivergence)

	return Divergence{
		StatusDiff:  statusDiff,
		LengthDiff:  lengthDiff,
		TimingDiff:  timingDiff,
		BodyDiff:    bodyDiff,
		BodyHash:    hash,
		SimScore:    sim,
		Significant: sig,
	}
}

// hashBody body hash üretir.
func hashBody(body []byte) string {
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}

// similarity iki body arası benzerlik skoru (basit Jaccard).
func similarity(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}
	setA := make(map[string]struct{})
	for _, w := range strings.Fields(string(a)) {
		setA[w] = struct{}{}
	}
	setB := make(map[string]struct{})
	for _, w := range strings.Fields(string(b)) {
		setB[w] = struct{}{}
	}
	intersection := 0
	for w := range setA {
		if _, ok := setB[w]; ok {
			intersection++
		}
	}
	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 1.0
	}
	return float64(intersection) / float64(union)
}

// fuzzValue indekse göre mutasyon değeri üretir.
func fuzzValue(kind string, idx int) string {
	values := map[string][]string{
		"param":  {"'", "\"", "<script>", "../../../etc/passwd", "1 OR 1=1", "true", "null", "undefined"},
		"form":   {"test", "' OR 1=1--", "<b>x</b>", "$(whoami)", "%00", "9999999999"},
		"json":   {"admin", "true", "null", "{};", "[]", "\"><img>", "1"},
		"header": {"127.0.0.1", "admin", "true", "null", "<script>", "*"},
		"cookie": {"admin", "true", "1", "null", "<script>", "../../../../etc/passwd"},
	}
	list, ok := values[kind]
	if !ok {
		return "fuzz"
	}
	return list[idx%len(list)]
}

func cloneHeaders(h map[string]string) map[string]string {
	if h == nil {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = v
	}
	return out
}

func abs(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

func snippet(body []byte, n int) string {
	if len(body) <= n {
		return string(body)
	}
	return string(body[:n])
}
