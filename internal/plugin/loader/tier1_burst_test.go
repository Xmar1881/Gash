// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package loader

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
)

const tier1RateLimit = `id: missing-rate-limit-test
name: Missing Rate Limit test build for unit tests
description: Unit test build for the budgeted burst runner with enough description length.
severity: medium
tags: [rate-limit, header]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 30
phase: probe
order: 71
api_version: "1.0"
tests: tests/fixtures/missing-rate-limit/
request:
  method: GET
oracle:
  name: header
  params:
    mode: "ratelimit"
    burst: 5
`

const tier1MassCeiling = `id: mass-assignment-test
name: Mass Assignment test build for unit tests here
description: Unit test build for the differential confidence ceiling with enough description length.
severity: high
tags: [mass-assignment, differential]
safe: false
deep: false
active: true
requires_auth: false
max_requests: 100
phase: probe
order: 69
api_version: "1.0"
tests: tests/fixtures/mass-assignment-basic/
request:
  method: GET
  param_names: [role]
  payload: "0"
oracle:
  name: differential
  params:
    repeats: 3
    false_payload: "gash-mass-inert"
    confidence_ceiling: "firm"
`

// TestTier1RateLimitBurst burst sayısını, tentative tavanı ve 429-kesintisini pinler.
// What: Mock Sender ile 5'li burst → 5 istek + tentative; 429'lu burst → bulgu YOK.
// Why: Fixture kapısı tek-örneklem tabanı ölçer; burst toplama mantığı burada kanıtlanır.
func TestTier1RateLimitBurst(t *testing.T) {
	spec, file, err := ParseTier1YAML("mem.yaml", []byte(tier1RateLimit))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var calls atomic.Int64
	sender := func(ctx context.Context, method, rawURL string, reqHeaders map[string]string, reqBody []byte) (int, http.Header, string, error) {
		calls.Add(1)
		return 200, http.Header{"Content-Type": []string{"text/html"}}, `<p>hi</p>`, nil
	}
	res, err := ExecuteTier1(context.Background(), spec, file, "http://example.com/login", sender)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if calls.Load() != 5 {
		t.Fatalf("burst=5 bekleniyordu, got %d", calls.Load())
	}
	if len(res) != 1 {
		t.Fatalf("tek tentative sonuç bekleniyordu: %+v", res)
	}
	if res[0].Evidence == nil || res[0].Evidence.ConfidenceContribution != plugin.ConfidenceTentative {
		t.Fatalf("tentative tavan bekleniyordu: %+v", res[0].Evidence)
	}
	if res[0].Evidence.Artifacts["burst"] != "5" {
		t.Fatalf("burst artifact taşınmalı: %+v", res[0].Evidence)
	}
	// Üçüncü istekte 429 → korumalı, bulgu YOK.
	var calls2 atomic.Int64
	sender429 := func(ctx context.Context, method, rawURL string, reqHeaders map[string]string, reqBody []byte) (int, http.Header, string, error) {
		n := calls2.Add(1)
		if n == 3 {
			return 429, http.Header{"Retry-After": []string{"60"}}, `<p>Too Many Requests</p>`, nil
		}
		return 200, http.Header{"Content-Type": []string{"text/html"}}, `<p>hi</p>`, nil
	}
	res, err = ExecuteTier1(context.Background(), spec, file, "http://example.com/login", sender429)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("429'lu burst bulgu üretmemeli: %+v", res)
	}
}

// TestTier1DifferentialCeiling tavanın gerçek Tier 1 akışında firm verdiğini pinler.
// What: true/false değerlerine göre gövde döndüren mock → tek firm sonucu.
// Why: plugintest kapısı fixture'ı ölçer; burası canlı executor + oracle
// birleşiminde tavanın çalıştığını kanıtlar (kanıt şişmesi YOK).
func TestTier1DifferentialCeiling(t *testing.T) {
	spec, file, err := ParseTier1YAML("mem.yaml", []byte(tier1MassCeiling))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sender := func(ctx context.Context, method, rawURL string, reqHeaders map[string]string, reqBody []byte) (int, http.Header, string, error) {
		h := http.Header{"Content-Type": []string{"application/json"}}
		switch {
		case strings.Contains(rawURL, "role=0"):
			return 200, h, `{"role":"0"}`, nil
		case strings.Contains(rawURL, "role=gash-mass-inert"):
			return 200, h, `{"role":"gash-mass-inert"}`, nil
		default:
			return 200, h, `{"role":"neutral"}`, nil
		}
	}
	res, err := ExecuteTier1(context.Background(), spec, file, "http://example.com/api", sender)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("tek firm sonuç bekleniyordu: %+v", res)
	}
	if res[0].Evidence == nil || res[0].Evidence.ConfidenceContribution != plugin.ConfidenceFirm {
		t.Fatalf("firm tavan bekleniyordu: %+v", res[0].Evidence)
	}
}
