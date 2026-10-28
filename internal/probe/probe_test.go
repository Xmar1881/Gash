// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/testutil/vcr"
)

func TestCanaryUnique(t *testing.T) {
	a := MustCanary()
	b := MustCanary()
	if a == b {
		t.Fatal("canary benzersiz olmalı")
	}
}

func TestNewClientBoundsResponseHeaders(t *testing.T) {
	c := NewClient(Options{})
	if got := c.Transport().MaxResponseHeaderBytes; got != 1<<20 {
		t.Fatalf("default response header limit = %d, want 1MiB", got)
	}
	if got := c.Transport().MaxIdleConnsPerHost; got < 32 {
		t.Fatalf("idle pool per host = %d, want >= 32", got)
	}
	if got := c.Transport().MaxIdleConns; got < 200 {
		t.Fatalf("idle pool = %d, want >= 200", got)
	}
	custom := &http.Transport{MaxResponseHeaderBytes: 4096}
	c2 := NewClient(Options{Transport: custom})
	if got := c2.Transport().MaxResponseHeaderBytes; got != 4096 {
		t.Fatalf("explicit header limit overwritten: %d", got)
	}
}

func TestSendClassifiesWAF(t *testing.T) {
	v := vcr.New()
	defer v.Close()
	v.AddRoute("GET", "/blocked", 200, nil, "<html>cf-chl</html>")
	policy := plugin.NewPolicySession(plugin.DefaultPolicyConfig(), nil)
	c := NewClient(Options{Policy: policy})
	ctx := plugin.WithPlugin(context.Background(), "t", true, nil)
	resp, err := c.Send(ctx, "GET", v.URL()+"/blocked", nil, nil)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !resp.Untrusted {
		t.Fatal("WAF yanıtı Untrusted işaretlenmeli")
	}
}

func TestSendAppliesRequestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	policy := plugin.NewPolicySession(plugin.PolicyConfig{}, nil)
	client := NewClient(Options{
		Policy:         policy,
		RequestTimeout: 20 * time.Millisecond,
	})
	ctx := plugin.WithPlugin(context.Background(), "timeout", true, nil)
	start := time.Now()
	_, err := client.Send(ctx, "GET", srv.URL, nil, nil)
	if err == nil {
		t.Fatal("blocked request must return a timeout")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("request timeout was not applied: elapsed=%v err=%v", elapsed, err)
	}
}
