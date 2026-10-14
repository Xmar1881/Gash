// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oob

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockProvider test için mock sağlayıcı.
type mockProvider struct {
	enabled   bool
	callback  *CallbackEvent
	delay     time.Duration
	callCount int
}

func (m *mockProvider) Type() ProviderType { return ProviderSelfHosted }
func (m *mockProvider) Name() string       { return "mock" }
func (m *mockProvider) Enabled() bool      { return m.enabled }

func (m *mockProvider) RegisterScan(ctx context.Context, scanID, corrID string) error {
	if !m.enabled {
		return ErrNotConfigured
	}
	return nil
}

func (m *mockProvider) PollCallback(ctx context.Context, corrID string) (*CallbackEvent, error) {
	m.callCount++
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return m.callback, nil
}

func (m *mockProvider) HTTPCallbackURL(corrID string) string {
	if !m.enabled {
		return ""
	}
	return "http://mock/cb/" + corrID
}

func (m *mockProvider) DNSCallbackDomain(corrID string) string {
	if !m.enabled {
		return ""
	}
	return corrID + ".mock"
}

func (m *mockProvider) Close() error { return nil }

func TestEngineDisabledProvider(t *testing.T) {
	e := NewEngine(EngineConfig{Provider: nil, Timeout: 100 * time.Millisecond, PollInt: 10 * time.Millisecond})
	if e.Enabled() {
		t.Fatal("provider yoksa kapalı olmalı")
	}
	res := e.Verify(context.Background(), "c1", "scan_x")
	if res.Verdict != VerdictNoCallback {
		t.Fatalf("provider yoksa VerdictNoCallback olmalı: %s", res.Verdict)
	}
}

func TestEngineVerifyConfirmed(t *testing.T) {
	mp := &mockProvider{
		enabled: true,
		callback: &CallbackEvent{
			CorrelationID: "c1",
			Protocol:      "http",
			RemoteIP:      "10.0.0.1",
			Timestamp:     time.Now(),
		},
	}
	e := NewEngine(EngineConfig{Provider: mp, Timeout: 5 * time.Second, PollInt: 10 * time.Millisecond})
	res := e.Verify(context.Background(), "c1", "scan_x")
	if res.Verdict != VerdictConfirmed {
		t.Fatalf("callback gelince confirmed olmalı: %s", res.Verdict)
	}
	if res.CorrelationID != "c1" {
		t.Fatal("correlation id eşleşmeli")
	}
	if res.Protocol != "http" {
		t.Fatal("protocol http olmalı")
	}
}

func TestEngineVerifyTimeout(t *testing.T) {
	mp := &mockProvider{
		enabled:  true,
		callback: nil,
		delay:    50 * time.Millisecond,
	}
	e := NewEngine(EngineConfig{Provider: mp, Timeout: 50 * time.Millisecond, PollInt: 10 * time.Millisecond})
	res := e.Verify(context.Background(), "c1", "scan_x")
	if res.Verdict != VerdictTentative {
		t.Fatalf("timeout'ta tentative olmalı: %s", res.Verdict)
	}
}

func TestEngineVerifyEmptyCorrID(t *testing.T) {
	mp := &mockProvider{enabled: true}
	e := NewEngine(EngineConfig{Provider: mp})
	res := e.Verify(context.Background(), "", "scan_x")
	if res.Verdict != VerdictNoCallback {
		t.Fatal("boş corrID no_callback olmalı")
	}
}

func TestEngineHTTPCallbackURL(t *testing.T) {
	mp := &mockProvider{enabled: true}
	e := NewEngine(EngineConfig{Provider: mp})
	u := e.HTTPCallbackURL("c1")
	if u == "" {
		t.Fatal("HTTP callback URL boş olmamalı")
	}
}

func TestEngineDNSCallbackDomain(t *testing.T) {
	mp := &mockProvider{enabled: true}
	e := NewEngine(EngineConfig{Provider: mp})
	d := e.DNSCallbackDomain("c1")
	if d == "" {
		t.Fatal("DNS callback domain boş olmamalı")
	}
}

func TestEngineCallbackURLDisabled(t *testing.T) {
	e := NewEngine(EngineConfig{Provider: nil})
	if u := e.HTTPCallbackURL("c1"); u != "" {
		t.Fatal("kapalı motor boş URL döndürmeli")
	}
}

func TestEngineDNSCallbackDisabled(t *testing.T) {
	e := NewEngine(EngineConfig{Provider: nil})
	if d := e.DNSCallbackDomain("c1"); d != "" {
		t.Fatal("kapalı motor boş domain döndürmeli")
	}
}

func TestEngineClose(t *testing.T) {
	mp := &mockProvider{enabled: true}
	e := NewEngine(EngineConfig{Provider: mp})
	if err := e.Close(); err != nil {
		t.Fatalf("close hatası: %v", err)
	}
}

func TestEngineVerifyAfterClose(t *testing.T) {
	mp := &mockProvider{enabled: true}
	e := NewEngine(EngineConfig{Provider: mp, Timeout: 50 * time.Millisecond, PollInt: 10 * time.Millisecond})
	_ = e.Close()
	res := e.Verify(context.Background(), "c1", "scan_x")
	if res.Verdict != VerdictNoCallback {
		t.Fatal("close sonrası no_callback olmalı")
	}
}

func TestEngineDefaultConfig(t *testing.T) {
	cfg := DefaultEngineConfig()
	if cfg.Timeout != 30*time.Second {
		t.Fatalf("varsayılan timeout 30s olmalı: %s", cfg.Timeout)
	}
	if cfg.PollInt != 2*time.Second {
		t.Fatalf("varsayılan poll 2s olmalı: %s", cfg.PollInt)
	}
}

func TestEngineVerdictString(t *testing.T) {
	if VerdictConfirmed.String() != "confirmed" {
		t.Fatal("confirmed metni yanlış")
	}
	if VerdictTentative.String() != "tentative" {
		t.Fatal("tentative metni yanlış")
	}
	if VerdictNoCallback.String() != "no_callback" {
		t.Fatal("no_callback metni yanlış")
	}
}

func TestEngineProviderPollsUntilTimeout(t *testing.T) {
	mp := &mockProvider{
		enabled:  true,
		callback: nil,
		delay:    10 * time.Millisecond,
	}
	e := NewEngine(EngineConfig{Provider: mp, Timeout: 100 * time.Millisecond, PollInt: 10 * time.Millisecond})
	start := time.Now()
	res := e.Verify(context.Background(), "c1", "scan_x")
	elapsed := time.Since(start)
	if res.Verdict != VerdictTentative {
		t.Fatalf("timeout'ta tentative olmalı: %s", res.Verdict)
	}
	if elapsed < 50*time.Millisecond {
		t.Fatalf("timeout beklemeli: %s", elapsed)
	}
}

func TestEngineCallbackAfterDelay(t *testing.T) {
	mp := &mockProvider{
		enabled: true,
		callback: &CallbackEvent{
			CorrelationID: "c1",
			Protocol:      "dns",
			RemoteIP:      "10.0.0.1",
		},
		delay: 50 * time.Millisecond,
	}
	e := NewEngine(EngineConfig{Provider: mp, Timeout: 5 * time.Second, PollInt: 10 * time.Millisecond})
	res := e.Verify(context.Background(), "c1", "scan_x")
	if res.Verdict != VerdictConfirmed {
		t.Fatalf("gecikmeli callback confirmed olmalı: %s", res.Verdict)
	}
	if res.Protocol != "dns" {
		t.Fatal("protocol dns olmalı")
	}
}

func TestEngineSelfHostedIntegration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("corr") == "c1" {
			_ = json.NewEncoder(w).Encode([]CallbackEvent{{
				CorrelationID: "c1",
				Protocol:      "http",
				RemoteIP:      "1.2.3.4",
				Timestamp:     time.Now(),
			}})
			return
		}
		_ = json.NewEncoder(w).Encode([]CallbackEvent{})
	}))
	defer srv.Close()

	p := NewSelfHostedProvider(srv.URL, "")
	e := NewEngine(EngineConfig{Provider: p, Timeout: 2 * time.Second, PollInt: 50 * time.Millisecond})
	res := e.Verify(context.Background(), "c1", "scan_x")
	if res.Verdict != VerdictConfirmed {
		t.Fatalf("confirmed olmalı: %s", res.Verdict)
	}
}
