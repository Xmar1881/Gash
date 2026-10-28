// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package loader

import (
	"context"
	"net/http"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// TestTier1HeaderPolicySkipIfMissing locks the directive/presence split:
// a missing header must not produce a second finding when the dedicated
// presence plugin owns it, while an existing header missing the directive
// still reaches firm.
func TestTier1HeaderPolicySkipIfMissing(t *testing.T) {
	spec := &plugin.PluginSpec{
		ID: "csp-default-src-missing", Name: "CSP default-src Missing",
		Description: "test spec", Severity: plugin.SeverityLow, Tags: []string{"headers"},
		Safe: true, Phase: plugin.PhaseProbe, APIVersion: "1.0",
	}
	file := &Tier1File{
		PluginSpec: *spec,
		Request:    Tier1Request{Method: http.MethodGet},
		Oracle: Tier1Oracle{Name: "header", Params: map[string]any{
			"mode": "policy", "header_name": "Content-Security-Policy",
			"policy": "required", "required_tokens": []any{"default-src"},
			"skip_if_header_missing": true,
		}},
	}
	run := func(headers http.Header) int {
		t.Helper()
		send := func(context.Context, string, string, map[string]string, []byte) (int, http.Header, string, error) {
			return http.StatusOK, headers, "<html><body>ok</body></html>", nil
		}
		results, err := ExecuteTier1(context.Background(), spec, file, "http://example.com/", send)
		if err != nil {
			t.Fatal(err)
		}
		return len(results)
	}
	if got := run(http.Header{}); got != 0 {
		t.Fatalf("missing header must not duplicate the presence finding, got %d results", got)
	}
	if got := run(http.Header{"Content-Security-Policy": {"default-src 'self'"}}); got != 0 {
		t.Fatalf("satisfied policy must stay clean, got %d results", got)
	}
	if got := run(http.Header{"Content-Security-Policy": {"script-src 'self'"}}); got != 1 {
		t.Fatalf("existing header without default-src must produce one result, got %d", got)
	}
}
