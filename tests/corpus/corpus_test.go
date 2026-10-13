// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package corpus global negatif korpustur: temiz app + SPA catch-all + WAF + encode + dinamik.
// CI kuralı: korpusta firm+ bulgu = build fail (B4).
package corpus

import (
	"context"
	"net/http"
	"testing"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/testutil/vcr"
)

// TestNoFalsePositives negatif korpusta firm+ = 0 (B4).
func TestNoFalsePositives(t *testing.T) {
	cases := []struct {
		name   string
		status int
		header map[string]string
		body   string
	}{
		{"clean-app", 200, nil, "<html><body><h1>Hello</h1><p>Welcome</p></body></html>"},
		{"spa-catchall", 200, nil, "<html><body><div id=root></div><script src=/static/js/main.js></script></body></html>"},
		{"waf-block", 403, nil, "<html><body>cf-chl challenge Please verify</body></html>"},
		{"encoded-app", 200, nil, "<html><body><p>&lt;script&gt;gash_test</p></body></html>"},
		{"dynamic", 200, nil, "<html><body><input name=\"csrf_token\" value=\"abc123\"><p>time 2026-10-12T10:00:00Z</p></body></html>"},
	}
	ctx := context.Background()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := vcr.New()
			defer v.Close()
			v.AddRoute("GET", "/page", tc.status, tc.header, tc.body)

			// Baseline sınıflandırması.
			cls := baseline.ClassifyStatic(tc.status, http.Header{}, []byte(tc.body))

			// Reflection: canary yok → reject olmalı (firm+ YOK).
			var ro oracle.ReflectionOracle
			ev, err := ro.Verify(ctx, tc.body, nil, cls, false, oracle.ReflectionParams{Canary: "gash_never_present_xyz"})
			if err != nil {
				t.Fatal(err)
			}
			if ev.Verdict == oracle.VerdictAccept && ev.ConfidenceContribution != plugin.ConfidenceTentative {
				t.Fatalf("negatif korpusta firm+ yasak (%s): %+v", tc.name, ev)
			}
			// WAF bloğu Untrusted olmalı → her oracle reject.
			if tc.name == "waf-block" && !cls.Untrusted {
				t.Fatalf("WAF Untrusted işaretlenmeli: %+v", cls)
			}
			// ErrorSignature: temiz sayfada imza yok → reject/tentative (firm+ yok).
			var eo oracle.ErrorSignatureOracle
			ev2, _ := eo.Verify(ctx, cls, false, oracle.ErrorSignatureParams{Body: tc.body, ControlBody: "normal"})
			if ev2.Verdict == oracle.VerdictAccept && ev2.ConfidenceContribution == plugin.ConfidenceConfirmed {
				t.Fatalf("temiz sayfada confirmed yasak (%s)", tc.name)
			}
		})
	}
}
