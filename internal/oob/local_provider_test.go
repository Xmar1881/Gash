// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oob

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestLocalProviderStartsAndListens(t *testing.T) {
	p, err := NewLocalProvider("")
	if err != nil {
		t.Fatalf("local provider başlatılamadı: %v", err)
	}
	defer p.Close()

	if !p.Enabled() {
		t.Fatal("local provider aktif olmalı")
	}
	if p.Type() != ProviderLocal {
		t.Fatalf("tür ProviderLocal olmalı, got %v", p.Type())
	}
	if p.Name() != "local" {
		t.Fatalf("ad 'local' olmalı, got %q", p.Name())
	}
	if p.Addr() == "" {
		t.Fatal("addr boş olmamalı")
	}
}

func TestLocalProviderHTTPCallbackURL(t *testing.T) {
	p, err := NewLocalProvider("")
	if err != nil {
		t.Fatalf("local provider başlatılamadı: %v", err)
	}
	defer p.Close()

	url := p.HTTPCallbackURL("c_test123")
	if url == "" {
		t.Fatal("callback URL boş olmamalı")
	}
	if !strings.Contains(url, "c_test123") {
		t.Fatalf("URL corrID içermeli: %q", url)
	}
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Fatalf("URL loopback olmalı: %q", url)
	}
}

func TestLocalProviderDNSCallbackDomain(t *testing.T) {
	p, err := NewLocalProvider("")
	if err != nil {
		t.Fatalf("local provider başlatılamadı: %v", err)
	}
	defer p.Close()

	d := p.DNSCallbackDomain("c_dns42")
	if d == "" {
		t.Fatal("DNS domain boş olmamalı")
	}
	if !strings.Contains(d, "c_dns42") {
		t.Fatalf("DNS domain corrID içermeli: %q", d)
	}
}

func TestLocalProviderCallbackAndPoll(t *testing.T) {
	p, err := NewLocalProvider("")
	if err != nil {
		t.Fatalf("local provider başlatılamadı: %v", err)
	}
	defer p.Close()

	// PollCallback: henüz callback yok
	ev, err := p.PollCallback(context.Background(), "c_abc123")
	if err != nil {
		t.Fatalf("poll hatası: %v", err)
	}
	if ev != nil {
		t.Fatal("callback yokken nil bekleniyor")
	}

	// HTTP callback tetikle
	cbURL := p.HTTPCallbackURL("c_abc123")
	resp, err := http.Get(cbURL)
	if err != nil {
		t.Fatalf("callback GET hatası: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback status 200 olmalı, got %d", resp.StatusCode)
	}

	// PollCallback: şimdi bulunmalı
	ev, err = p.PollCallback(context.Background(), "c_abc123")
	if err != nil {
		t.Fatalf("poll hatası: %v", err)
	}
	if ev == nil {
		t.Fatal("callback sonrası event bulunmalı")
	}
	if ev.CorrelationID != "c_abc123" {
		t.Fatalf("corrID eşleşmeli, got %q", ev.CorrelationID)
	}
	if ev.Protocol != "http" {
		t.Fatalf("protocol 'http' olmalı, got %q", ev.Protocol)
	}
}

func TestLocalProviderPollNoMatch(t *testing.T) {
	p, err := NewLocalProvider("")
	if err != nil {
		t.Fatalf("local provider başlatılamadı: %v", err)
	}
	defer p.Close()

	// Farklı bir corrID ile callback tetikle
	cbURL := p.HTTPCallbackURL("c_other")
	resp, err := http.Get(cbURL)
	if err != nil {
		t.Fatalf("callback GET hatası: %v", err)
	}
	resp.Body.Close()

	// Eşleşmeyen corrID sorgusu
	ev, err := p.PollCallback(context.Background(), "c_notfound")
	if err != nil {
		t.Fatalf("poll hatası: %v", err)
	}
	if ev != nil {
		t.Fatal("eşleşme yoksa nil döndürmeli")
	}
}

func TestLocalProviderRegisterScan(t *testing.T) {
	p, err := NewLocalProvider("")
	if err != nil {
		t.Fatalf("local provider başlatılamadı: %v", err)
	}
	defer p.Close()

	if err := p.RegisterScan(context.Background(), "scan_x", "c_y"); err != nil {
		t.Fatalf("register no-op olmalı: %v", err)
	}
}

func TestLocalProviderClose(t *testing.T) {
	p, err := NewLocalProvider("")
	if err != nil {
		t.Fatalf("local provider başlatılamadı: %v", err)
	}

	addr := p.Addr()
	if addr == "" {
		t.Fatal("addr boş olmamalı")
	}

	if err := p.Close(); err != nil {
		t.Fatalf("close hatası: %v", err)
	}

	if p.Enabled() {
		t.Fatal("close sonrası kapalı olmalı")
	}

	// İkinci close idempotent
	if err := p.Close(); err != nil {
		t.Fatalf("ikinci close hata vermemeli: %v", err)
	}

	// Callback URL kapalı provider'dan boş döner
	if url := p.HTTPCallbackURL("c_z"); url != "" {
		t.Fatalf("kapalı provider boş URL döndürmeli, got %q", url)
	}
}

func TestLocalProviderDisabledPoll(t *testing.T) {
	p, err := NewLocalProvider("")
	if err != nil {
		t.Fatalf("local provider başlatılamadı: %v", err)
	}
	_ = p.Close()

	_, err = p.PollCallback(context.Background(), "c_x")
	if err == nil {
		t.Fatal("kapalı provider poll hata vermeli")
	}
}

func TestLocalProviderWaitForCallback(t *testing.T) {
	p, err := NewLocalProvider("")
	if err != nil {
		t.Fatalf("local provider başlatılamadı: %v", err)
	}
	defer p.Close()

	// Arka planda callback tetikle
	go func() {
		time.Sleep(50 * time.Millisecond)
		cbURL := p.HTTPCallbackURL("c_wait")
		resp, _ := http.Get(cbURL)
		if resp != nil {
			resp.Body.Close()
		}
	}()

	// WaitForCallback ile bekleme
	ev, ok := WaitForCallback(context.Background(), p, "c_wait", 2*time.Second, 10)
	if !ok {
		t.Fatal("callback geldi, ok=true olmalı")
	}
	if ev == nil {
		t.Fatal("event nil olmamalı")
	}
	if ev.CorrelationID != "c_wait" {
		t.Fatalf("corrID eşleşmeli, got %q", ev.CorrelationID)
	}
}

func TestLocalProviderWithLocalKeyword(t *testing.T) {
	p, err := NewLocalProvider("local")
	if err != nil {
		t.Fatalf("local keyword ile başlatılamadı: %v", err)
	}
	defer p.Close()

	if !p.Enabled() {
		t.Fatal("provider aktif olmalı")
	}
}
