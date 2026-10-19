// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package oracle

import (
	"context"
	"net/http"
	"testing"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/plugin"
)

func TestMiddlewareBypassOracle(t *testing.T) {
	base := MiddlewareBypassParams{
		ControlStatus:   302,
		ControlLocation: "/login?next=/admin",
		ControlBody:     "<html>redirecting to login</html>",
		BypassStatus:    200,
		BypassBody:      "<html><body>Admin dashboard user list and settings</body></html>",
		Header:          "x-middleware-subrequest",
		HeaderValue:     "middleware",
		Path:            "/admin",
	}
	tests := []struct {
		name   string
		mutate func(*MiddlewareBypassParams)
		cls    baseline.Classification
		accept bool
		conf   plugin.Confidence
	}{
		{
			name:   "redirect to login then 200 content accepts",
			accept: true,
			conf:   plugin.ConfidenceFirm,
		},
		{
			name: "401 then 200 content accepts",
			mutate: func(p *MiddlewareBypassParams) {
				p.ControlStatus = 401
				p.ControlLocation = ""
				p.ControlBody = "unauthorized"
			},
			accept: true,
			conf:   plugin.ConfidenceFirm,
		},
		{
			name: "header echoed but still redirected rejects",
			mutate: func(p *MiddlewareBypassParams) {
				p.BypassStatus = 302
				p.BypassBody = "<html>redirecting to login</html>"
			},
		},
		{
			name: "identical body rejects",
			mutate: func(p *MiddlewareBypassParams) {
				p.ControlStatus = 401
				p.ControlBody = "<html><body>Admin dashboard user list and settings</body></html>"
			},
		},
		{
			name: "waf block body rejects",
			mutate: func(p *MiddlewareBypassParams) {
				p.BypassBody = "<html><title>Attention Required! | Cloudflare</title><body>Request blocked by WAF</body></html>"
			},
		},
		{
			name: "public route 200 to 200 rejects",
			mutate: func(p *MiddlewareBypassParams) {
				p.ControlStatus = 200
				p.ControlLocation = ""
				p.ControlBody = "<html>public page</html>"
				p.BypassBody = "<html>public page with header echoed</html>"
			},
		},
		{
			name: "redirect without login location rejects",
			mutate: func(p *MiddlewareBypassParams) {
				p.ControlLocation = "/products"
			},
		},
		{
			name: "author path is not a login redirect",
			mutate: func(p *MiddlewareBypassParams) {
				p.ControlLocation = "/authors/42"
			},
		},
		{
			name: "untrusted bypass response rejects",
			cls:  baseline.Classification{Untrusted: true, WAFDetected: true, Note: "waf"},
		},
		{
			name: "tiny bypass body rejects",
			mutate: func(p *MiddlewareBypassParams) {
				p.BypassBody = "OK"
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			if tc.mutate != nil {
				tc.mutate(&p)
			}
			ev, err := (MiddlewareBypassOracle{}).Verify(context.Background(), tc.cls, false, p)
			if err != nil {
				t.Fatal(err)
			}
			if tc.accept {
				if ev.Verdict != VerdictAccept {
					t.Fatalf("want accept, got %s (%s)", ev.Verdict, ev.Note)
				}
				if ev.ConfidenceContribution != tc.conf {
					t.Fatalf("confidence %s want %s", ev.ConfidenceContribution, tc.conf)
				}
				if ev.Artifacts["path"] != "/admin" || ev.Artifacts["header"] != "x-middleware-subrequest" {
					t.Fatalf("missing artifacts: %#v", ev.Artifacts)
				}
				return
			}
			if ev.Verdict != VerdictReject {
				t.Fatalf("want reject, got %s", ev.Verdict)
			}
		})
	}
}

func TestMiddlewareControlDenied(t *testing.T) {
	cases := []struct {
		status int
		loc    string
		want   bool
	}{
		{http.StatusUnauthorized, "", true},
		{http.StatusForbidden, "", true},
		{http.StatusFound, "/login?next=/admin", true},
		{http.StatusTemporaryRedirect, "/auth/signin", true},
		{http.StatusFound, "/authors", false},
		{http.StatusFound, "", false},
		{http.StatusOK, "/login", false},
		{http.StatusNotFound, "/login", false},
	}
	for _, tc := range cases {
		if got := MiddlewareControlDenied(tc.status, tc.loc); got != tc.want {
			t.Fatalf("MiddlewareControlDenied(%d,%q)=%v want %v", tc.status, tc.loc, got, tc.want)
		}
	}
}
