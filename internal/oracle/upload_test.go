// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oracle

import (
	"context"
	"net/http"
	"testing"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// TestUploadServedLadder locks the upload serve-back evidence ladder.
// What: One table covers accept, firm, and every rejection reason.
// Why: The ladder is the only thing separating an accepted upload (meaningless)
// from executable serve-back content (a finding).
func TestUploadServedLadder(t *testing.T) {
	const canary = "gash_up_1"
	const payload = `<svg onload="alert(gash_up_1)"></svg>`
	ct := func(v string) http.Header { return http.Header{"Content-Type": []string{v}} }

	base := UploadServedParams{
		Canary:        canary,
		UploadStatus:  200,
		UploadBody:    `{"url":"/uploads/gash_up_1.html"}`,
		FetchStatus:   200,
		FetchHeaders:  ct("text/html"),
		FetchBody:     payload,
		ControlStatus: 404,
		ControlBody:   "<html><body>not found</body></html>",
	}

	tests := []struct {
		name       string
		mutate     func(*UploadServedParams)
		verdict    Verdict
		confidence plugin.Confidence
	}{
		{"active html confirms", func(p *UploadServedParams) {}, VerdictAccept, plugin.ConfidenceConfirmed},
		{"svg with charset confirms", func(p *UploadServedParams) { p.FetchHeaders = ct("image/svg+xml; charset=utf-8") }, VerdictAccept, plugin.ConfidenceConfirmed},
		{"active type case insensitive", func(p *UploadServedParams) { p.FetchHeaders = ct("TEXT/HTML") }, VerdictAccept, plugin.ConfidenceConfirmed},
		{"plain text firms", func(p *UploadServedParams) { p.FetchHeaders = ct("text/plain") }, VerdictAccept, plugin.ConfidenceFirm},
		{"unknown type firms", func(p *UploadServedParams) { p.FetchHeaders = http.Header{} }, VerdictAccept, plugin.ConfidenceFirm},
		{"caller supplied active type confirms", func(p *UploadServedParams) {
			p.FetchHeaders = ct("application/pdf")
			p.ActiveTypes = []string{"application/pdf"}
		}, VerdictAccept, plugin.ConfidenceConfirmed},
		{"upload rejected", func(p *UploadServedParams) { p.UploadStatus = 415 }, VerdictReject, ""},
		{"upload exchange missing", func(p *UploadServedParams) {
			p.UploadStatus = 0
			p.UploadBody = ""
		}, VerdictReject, ""},
		{"artifact not retrievable", func(p *UploadServedParams) { p.FetchStatus = 404 }, VerdictReject, ""},
		{"fetch exchange missing", func(p *UploadServedParams) { p.FetchStatus = 0 }, VerdictReject, ""},
		{"served body without payload", func(p *UploadServedParams) { p.FetchBody = "<p>image preview unavailable</p>" }, VerdictReject, ""},
		{"dirty control loses attribution", func(p *UploadServedParams) { p.ControlBody = payload }, VerdictReject, ""},
		{"empty canary", func(p *UploadServedParams) { p.Canary = "" }, VerdictReject, ""},
	}

	var o UploadServedOracle
	if got := o.Name(); got != "upload-served" {
		t.Fatalf("unexpected oracle name %q", got)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			tc.mutate(&p)
			ev, err := o.Verify(context.Background(), cls(), false, p)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if ev == nil {
				t.Fatal("nil evidence")
			}
			if ev.Verdict != tc.verdict {
				t.Fatalf("verdict = %s (%s), want %s", ev.Verdict, ev.Note, tc.verdict)
			}
			if tc.verdict == VerdictAccept && ev.ConfidenceContribution != tc.confidence {
				t.Fatalf("confidence = %s, want %s", ev.ConfidenceContribution, tc.confidence)
			}
		})
	}
}

// TestUploadServedUntrustedBaseline guards the shared baseline discipline.
func TestUploadServedUntrustedBaseline(t *testing.T) {
	var o UploadServedOracle
	ev, err := o.Verify(context.Background(), baseline.Classification{Untrusted: true, WAFDetected: true, Note: "waf"}, false, UploadServedParams{
		Canary:       "gash_up_2",
		UploadStatus: 200,
		FetchStatus:  200,
		FetchBody:    `alert(gash_up_2)`,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ev == nil || ev.Verdict == VerdictAccept {
		t.Fatalf("untrusted baseline must not accept: %+v", ev)
	}
}
