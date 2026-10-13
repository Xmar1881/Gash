// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package probe

import (
	"context"
	"testing"

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
