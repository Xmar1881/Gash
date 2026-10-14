// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package oracle

import (
	"context"
	"net/http"
	"testing"
)

// TestCookieBareConfirmed locks the bare-cookie confirmed path.
// What: Single flagless cookie on https must confirm.
// Why: Missing HttpOnly is directly XSS-stealable; no control needed.
func TestCookieBareConfirmed(t *testing.T) {
	var o CookieOracle
	h := http.Header{}
	h.Set("Set-Cookie", "sessionid=abc; Path=/")
	ev, err := o.Verify(context.Background(), cls(), false, CookieParams{Headers: h, Target: "https://example.com/"})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "confirmed" {
		t.Fatalf("bare cookie confirmed bekleniyordu: %+v", ev)
	}
}

// TestCookieSameSiteFirm locks the hardening-gap firm path.
// What: HttpOnly plus Secure present but SameSite missing must firm, not confirm.
// Why: SameSite absence is CSRF hardening, not direct theft.
func TestCookieSameSiteFirm(t *testing.T) {
	var o CookieOracle
	h := http.Header{}
	h.Set("Set-Cookie", "id=1; Secure; HttpOnly; Path=/")
	ev, err := o.Verify(context.Background(), cls(), false, CookieParams{Headers: h, Target: "https://example.com/"})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "firm" {
		t.Fatalf("samesite-only firm bekleniyordu: %+v", ev)
	}
}

// TestCookieHardenedReject locks the negative path.
// What: Fully flagged cookie must reject.
// Why: No gap means no finding; negatives must never reach firm-plus.
func TestCookieHardenedReject(t *testing.T) {
	var o CookieOracle
	h := http.Header{}
	h.Set("Set-Cookie", "session=abc; Secure; HttpOnly; SameSite=Strict; Path=/")
	ev, err := o.Verify(context.Background(), cls(), false, CookieParams{Headers: h, Target: "https://example.com/"})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictReject {
		t.Fatalf("hardened reject bekleniyordu: %+v", ev)
	}
}

// TestCookieNoCookieReject locks the empty path.
// What: No Set-Cookie must reject.
// Why: Cookie oracle must not fire on cookie-less responses.
func TestCookieNoCookieReject(t *testing.T) {
	var o CookieOracle
	ev, err := o.Verify(context.Background(), cls(), false, CookieParams{Headers: http.Header{}, Target: "https://example.com/"})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictReject {
		t.Fatalf("cookie-less reject bekleniyordu: %+v", ev)
	}
}

// TestCORSWildcardCredentialsConfirmed locks the critical CORS path.
// What: ACAO "*" with credentials must confirm.
// Why: Wildcard plus credentials is deterministic misconfiguration.
func TestCORSWildcardCredentialsConfirmed(t *testing.T) {
	var o CORSOracle
	h := http.Header{}
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Credentials", "true")
	ev, err := o.Verify(context.Background(), cls(), false, CORSParams{Headers: h})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "confirmed" {
		t.Fatalf("wildcard+creds confirmed bekleniyordu: %+v", ev)
	}
}

// TestCORSPlainWildcardFirm locks the permissive firm path.
// What: Plain "*" without credentials must firm.
// Why: Overly permissive but not directly credentialed.
func TestCORSPlainWildcardFirm(t *testing.T) {
	var o CORSOracle
	h := http.Header{}
	h.Set("Access-Control-Allow-Origin", "*")
	ev, err := o.Verify(context.Background(), cls(), false, CORSParams{Headers: h})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "firm" {
		t.Fatalf("plain wildcard firm bekleniyordu: %+v", ev)
	}
}

// TestCORSReflectedConfirmed locks the reflected-origin path.
// What: Echoed Origin with credentials must confirm.
// Why: Arbitrary-origin reflection is the active CORS primitive.
func TestCORSReflectedConfirmed(t *testing.T) {
	var o CORSOracle
	h := http.Header{}
	h.Set("Access-Control-Allow-Origin", "https://evil.example")
	h.Set("Access-Control-Allow-Credentials", "true")
	ev, err := o.Verify(context.Background(), cls(), false, CORSParams{Headers: h, RequestOrigin: "https://evil.example"})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictAccept || ev.ConfidenceContribution != "confirmed" {
		t.Fatalf("reflected+creds confirmed bekleniyordu: %+v", ev)
	}
}

// TestCORSNoHeaderReject locks the negative path.
// What: Missing ACAO must reject.
// Why: No CORS header means no CORS finding.
func TestCORSNoHeaderReject(t *testing.T) {
	var o CORSOracle
	ev, err := o.Verify(context.Background(), cls(), false, CORSParams{Headers: http.Header{}})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Verdict != VerdictReject {
		t.Fatalf("no-acao reject bekleniyordu: %+v", ev)
	}
}
