// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package headless

import (
	"errors"
	"strings"
	"testing"
)

func TestResultOutcome(t *testing.T) {
	tests := []struct {
		name string
		res  Result
		want Outcome
	}{
		{
			name: "trigger with clean control is confirmed",
			res:  Result{Triggered: true, ControlClean: true, PayloadStatus: 200, ControlStatus: 200},
			want: OutcomeConfirmed,
		},
		{
			name: "trigger with dirty control is candidate",
			res:  Result{Triggered: true, ControlClean: false, PayloadStatus: 200, ControlStatus: 200},
			want: OutcomeCandidate,
		},
		{
			name: "no trigger with clean control is not vulnerable",
			res:  Result{Triggered: false, ControlClean: true, PayloadStatus: 200, ControlStatus: 200},
			want: OutcomeNotVulnerable,
		},
		{
			name: "waf block is blocked, not not-vulnerable",
			res:  Result{Triggered: false, ControlClean: true, PayloadStatus: 403, ControlStatus: 403},
			want: OutcomeBlocked,
		},
		{
			name: "200 challenge page is blocked",
			res:  Result{Triggered: false, ControlClean: true, PayloadStatus: 200, ControlStatus: 200, PayloadChallenge: true},
			want: OutcomeBlocked,
		},
		{
			name: "throttle is blocked",
			res:  Result{Triggered: false, ControlClean: true, PayloadStatus: 200, ControlStatus: 429},
			want: OutcomeBlocked,
		},
		{
			name: "server error is error, not not-vulnerable",
			res:  Result{Triggered: false, ControlClean: true, PayloadStatus: 500, ControlStatus: 200},
			want: OutcomeError,
		},
		{
			name: "untrustworthy control without status is unverified",
			res:  Result{Triggered: false, ControlClean: false},
			want: OutcomeUnverified,
		},
		{
			name: "request timeout is error, not not-vulnerable",
			res:  Result{Triggered: false, ControlClean: true, PayloadStatus: 408, ControlStatus: 200},
			want: OutcomeError,
		},
		{
			name: "blocked control invalidates a trigger",
			res:  Result{Triggered: true, ControlClean: true, PayloadStatus: 200, ControlStatus: 403},
			want: OutcomeBlocked,
		},
		{
			name: "server-error control invalidates a trigger",
			res:  Result{Triggered: true, ControlClean: true, PayloadStatus: 200, ControlStatus: 503},
			want: OutcomeError,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.res.Outcome(); got != tc.want {
				t.Fatalf("Outcome() = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestHTTPReason(t *testing.T) {
	tests := map[int]string{
		401: "auth_required",
		403: "forbidden",
		407: "proxy_auth_required",
		408: "request_timeout",
		429: "rate_limited",
		451: "legal_block",
		500: "server_error",
		503: "server_error",
		418: "",
		200: "",
	}
	for status, want := range tests {
		if got := HTTPReason(status); got != want {
			t.Errorf("HTTPReason(%d) = %q, want %q", status, got, want)
		}
	}
}

func TestResultReasonAndVerifyError(t *testing.T) {
	res := Result{PayloadStatus: 403, ControlStatus: 200, ControlClean: true}
	if got, want := res.Reason(), "payload_forbidden"; got != want {
		t.Fatalf("Reason() = %q, want %q", got, want)
	}
	var statusErr *StatusError
	if err := res.VerifyError(); !errors.As(err, &statusErr) {
		t.Fatalf("VerifyError() = %v, want *StatusError", err)
	} else if statusErr.Outcome != OutcomeBlocked || statusErr.Reason != "payload_forbidden" {
		t.Fatalf("StatusError = %+v", statusErr)
	}

	control := Result{PayloadStatus: 200, ControlStatus: 429}
	if got, want := control.Reason(), "control_rate_limited"; got != want {
		t.Fatalf("Reason() = %q, want %q", got, want)
	}
	if got := control.Outcome(); got != OutcomeBlocked {
		t.Fatalf("Outcome() = %s, want blocked", got)
	}

	clean := Result{ControlClean: true, PayloadStatus: 200, ControlStatus: 200}
	if err := clean.VerifyError(); err != nil {
		t.Fatalf("VerifyError() on clean proof = %v, want nil", err)
	}
}

func TestChallengeReason(t *testing.T) {
	if got := (Result{PayloadChallenge: true}).Reason(); got != "payload_waf_challenge" {
		t.Fatalf("payload challenge reason = %q", got)
	}
	if got := (Result{ControlChallenge: true}).Reason(); got != "control_waf_challenge" {
		t.Fatalf("control challenge reason = %q", got)
	}
}

func TestCanaryTokenIsUniqueAndProbeUsesIt(t *testing.T) {
	first, err := newCanaryToken()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newCanaryToken()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || len(first) != 32 {
		t.Fatalf("tokens must be unique 32-char hex, got %q and %q", first, second)
	}
	probe := xssCanaryProbe(first)
	if !strings.Contains(probe, first) || strings.Contains(probe, "__gash_canary") {
		t.Fatalf("probe must require the run token and not accept node insertion: %s", probe)
	}
	if bootstrap := xssCanaryBootstrap(first); !strings.Contains(bootstrap, first) {
		t.Fatalf("bootstrap must install the run token: %s", bootstrap)
	}
}
