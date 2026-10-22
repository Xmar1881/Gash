//go:build deep

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/headless"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// TestDeepBrowserVerifyDOMFinding exercises the real deep-build verifier
// through the engine: a live hash sink is confirmed, while a WAF-blocked page
// stays firm and is reported as a skip instead of a clean negative.
func TestDeepBrowserVerifyDOMFinding(t *testing.T) {
	if !headless.Available() {
		t.Skip("headless yok: chrome bulunamadi, skip")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/dom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><html><body><div id="sink"></div><script>
var raw = location.hash.indexOf('?') >= 0 ? location.hash.split('?')[1] : '';
var q = new URLSearchParams(raw).get('q') || '';
document.getElementById('sink').innerHTML = q;
</script></body></html>`)
	})
	mux.HandleFunc("/blocked", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "local WAF")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	payload := `<img src=x onerror="window.__gashCanary=true">`
	domFinding := func(target string) *finding.Finding {
		return &finding.Finding{
			RuleID:     "GASH-003",
			Confidence: plugin.ConfidenceFirm,
			Target:     target + "#/search?q=1",
			InjectionPoint: plugin.InjectionPoint{
				URL: target + "#/search", Method: http.MethodGet,
				ParamName: "q", ParamLocation: "fragment", Value: payload,
			},
			Evidence:        map[string]string{"sink": "innerHTML", "source": "location.hash"},
			Reproducibility: map[string]string{"repeats": "1"},
			Note:            "static sink/source",
		}
	}

	e := &Engine{cfg: Config{BrowserVerify: true}}
	confirmed := domFinding(srv.URL + "/dom")
	if skipped := e.verifyBrowserFindings(context.Background(), []*finding.Finding{confirmed}); len(skipped) != 0 {
		t.Fatalf("unexpected skip: %+v", skipped)
	}
	if confirmed.Confidence != plugin.ConfidenceConfirmed {
		t.Fatalf("live hash sink must be browser-confirmed, got %s", confirmed.Confidence)
	}
	if confirmed.Evidence["execution"] != "browser-confirmed" {
		t.Fatalf("missing browser evidence: %+v", confirmed.Evidence)
	}
	if confirmed.Evidence["browser_verify_scope"] != "tested payload/control pair only" {
		t.Fatalf("confirmed evidence must state its narrow scope: %+v", confirmed.Evidence)
	}

	blocked := domFinding(srv.URL + "/blocked")
	skipped := e.verifyBrowserFindings(context.Background(), []*finding.Finding{blocked})
	if len(skipped) != 1 || !strings.Contains(skipped[0].Reason, "reason=payload_forbidden") {
		t.Fatalf("blocked page must preserve the forbidden reason code, got %+v", skipped)
	}
	if blocked.Confidence != plugin.ConfidenceFirm {
		t.Fatalf("blocked page must keep the firm tier, got %s", blocked.Confidence)
	}
}
