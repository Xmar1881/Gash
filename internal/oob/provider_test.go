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

func TestSelfHostedProviderDisabled(t *testing.T) {
	p := NewSelfHostedProvider("", "")
	if p.Enabled() {
		t.Fatal("boş URL provider kapalı olmalı")
	}
	if _, err := p.PollCallback(context.Background(), "c1"); err == nil {
		t.Fatal("kapalı provider hata vermeli")
	}
	if err := p.RegisterScan(context.Background(), "s", "c"); err == nil {
		t.Fatal("kapalı provider register hata vermeli")
	}
}

func TestSelfHostedProviderEnabled(t *testing.T) {
	p := NewSelfHostedProvider("http://localhost:9999", "tok")
	if !p.Enabled() {
		t.Fatal("provider açık olmalı")
	}
	if p.Type() != ProviderSelfHosted {
		t.Fatal("tür self-hosted olmalı")
	}
	if p.Name() != "self-hosted" {
		t.Fatal("ad self-hosted olmalı")
	}
}

func TestSelfHostedProviderPollCallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/poll" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		q := r.URL.Query().Get("corr")
		if q == "c_hit" {
			_ = json.NewEncoder(w).Encode([]CallbackEvent{{
				CorrelationID: "c_hit",
				ScanID:        "scan_x",
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
	if !p.Enabled() {
		t.Fatal("provider açık olmalı")
	}

	ev, err := p.PollCallback(context.Background(), "c_hit")
	if err != nil {
		t.Fatalf("poll hatası: %v", err)
	}
	if ev == nil {
		t.Fatal("callback event bulunmalı")
	}
	if ev.CorrelationID != "c_hit" {
		t.Fatal("correlation eşleşmeli")
	}
	if ev.Protocol != "http" {
		t.Fatal("protocol http olmalı")
	}
}

func TestSelfHostedProviderPollNoMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]CallbackEvent{{
			CorrelationID: "other",
			ScanID:        "scan_x",
		}})
	}))
	defer srv.Close()

	p := NewSelfHostedProvider(srv.URL, "")
	ev, err := p.PollCallback(context.Background(), "c_missing")
	if err != nil {
		t.Fatalf("poll hatası: %v", err)
	}
	if ev != nil {
		t.Fatal("eşleşme yoksa nil döndürmeli")
	}
}

func TestSelfHostedProviderHTTPCallbackURL(t *testing.T) {
	p := NewSelfHostedProvider("http://example.com:8080", "")
	u := p.HTTPCallbackURL("c_abc")
	if u == "" {
		t.Fatal("HTTP callback URL boş olmamalı")
	}
}

func TestSelfHostedProviderDNSCallbackDomain(t *testing.T) {
	p := NewSelfHostedProvider("http://example.com:8080", "")
	d := p.DNSCallbackDomain("c_abc")
	if d == "" {
		t.Fatal("DNS callback domain boş olmamalı")
	}
}

func TestSelfHostedProviderClose(t *testing.T) {
	p := NewSelfHostedProvider("http://localhost:9999", "")
	if err := p.Close(); err != nil {
		t.Fatalf("close hatası: %v", err)
	}
	if p.Enabled() {
		t.Fatal("close sonrası kapalı olmalı")
	}
}

func TestSelfHostedProviderRegisterScan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := NewSelfHostedProvider(srv.URL, "")
	if err := p.RegisterScan(context.Background(), "scan_1", "c_1"); err != nil {
		t.Fatalf("register hatası: %v", err)
	}
}

func TestSelfHostedProviderTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := NewSelfHostedProvider(srv.URL, "")
	p.timeout = 10 * time.Millisecond
	_, err := p.PollCallback(context.Background(), "c1")
	if err == nil {
		t.Fatal("timeout hata vermeli")
	}
}

func TestSelfHostedProviderDisabledAfterClose(t *testing.T) {
	p := NewSelfHostedProvider("http://localhost:9999", "")
	_ = p.Close()
	if _, err := p.PollCallback(context.Background(), "c1"); err == nil {
		t.Fatal("close sonrası poll hata vermeli")
	}
}

func TestSelfHostedProviderHTTPCallbackDisabled(t *testing.T) {
	p := NewSelfHostedProvider("", "")
	if u := p.HTTPCallbackURL("c1"); u != "" {
		t.Fatal("kapalı provider boş URL döndürmeli")
	}
}

func TestSelfHostedProviderDNSCallbackDisabled(t *testing.T) {
	p := NewSelfHostedProvider("", "")
	if d := p.DNSCallbackDomain("c1"); d != "" {
		t.Fatal("kapalı provider boş domain döndürmeli")
	}
}
